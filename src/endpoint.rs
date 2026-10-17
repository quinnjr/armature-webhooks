//! Webhook endpoint configuration

use crate::{Result, WebhookError};
use armature_http_client::egress::EgressPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use uuid::Uuid;

/// Custom endpoint header names that are refused (compared
/// case-insensitively).
///
/// - `host`: would re-target virtual hosting / SNI-routed internal services.
/// - `authorization`, `cookie`, `proxy-*`: credentials for *someone else's*
///   service have no business on an outbound webhook, and are the classic
///   payload of a request-forgery chain.
/// - `metadata*` (incl. `metadata-flavor`), `x-aws-ec2-metadata-token*`,
///   `x-google-metadata-request`: the headers cloud metadata services require
///   as their SSRF defence; letting a tenant set them disables that defence.
/// - hop-by-hop and framing headers (`connection`, `keep-alive`, `te`,
///   `trailer`, `upgrade`, `transfer-encoding`, `content-length`, `expect`):
///   request smuggling and desync.
/// - `content-type`, `content-encoding`, `x-webhook-*`, `x-hub-signature*`:
///   set by the sender; a tenant overriding them could make a receiver
///   misparse or mis-verify the delivery.
/// - `forwarded`, `x-forwarded-*`, `x-real-ip`, `via`: spoof the sender's
///   network identity to a receiver that trusts them.
const DENIED_EXACT: &[&str] = &[
    "host",
    "authorization",
    "cookie",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "transfer-encoding",
    "content-length",
    "content-type",
    "content-encoding",
    "expect",
    "forwarded",
    "via",
    "x-real-ip",
    "x-google-metadata-request",
];
const DENIED_PREFIXES: &[&str] = &[
    "metadata",
    "x-aws-ec2-metadata-token",
    "proxy-",
    "x-webhook-",
    "x-hub-signature",
    "x-forwarded-",
];

/// True if `name` may not be set as a custom endpoint header.
pub fn is_denied_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    DENIED_EXACT.contains(&name.as_str()) || DENIED_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// A registered webhook endpoint
///
/// `Debug` redacts the secret and custom header values (which commonly carry
/// API keys).
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Unique endpoint ID
    pub id: String,

    /// Target URL for webhook delivery
    pub url: String,

    /// Signing secret for this endpoint
    #[serde(skip_serializing)]
    pub secret: String,

    /// Events this endpoint is subscribed to
    pub events: HashSet<String>,

    /// Whether this endpoint is active
    pub enabled: bool,

    /// Description for this endpoint
    pub description: Option<String>,

    /// Custom headers to include with requests
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Updated timestamp
    pub updated_at: DateTime<Utc>,

    /// Last successful delivery timestamp
    pub last_success: Option<DateTime<Utc>>,

    /// Last failed delivery timestamp
    pub last_failure: Option<DateTime<Utc>>,

    /// Consecutive failure count
    pub failure_count: u32,
}

impl fmt::Debug for WebhookEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&String> = self.headers.keys().collect();
        f.debug_struct("WebhookEndpoint")
            .field("id", &self.id)
            .field("url", &self.url)
            .field("secret", &"[REDACTED]")
            .field("events", &self.events)
            .field("enabled", &self.enabled)
            .field("description", &self.description)
            .field("headers", &header_names)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_success", &self.last_success)
            .field("last_failure", &self.last_failure)
            .field("failure_count", &self.failure_count)
            .finish()
    }
}

impl WebhookEndpoint {
    /// Check the endpoint against `policy` and the crate's invariants.
    ///
    /// - the URL parses and passes [`EgressPolicy::check_url`] (scheme, IP
    ///   literal ranges, internal host names);
    /// - every custom header is a valid header and not on the deny list (see
    ///   [`is_denied_header`]);
    /// - the secret is at least
    ///   [`MIN_SECRET_LEN`](crate::MIN_SECRET_LEN) bytes.
    ///
    /// DNS answers are vetted later, at delivery time, since they can change.
    /// This runs in [`WebhookEndpointBuilder::build`],
    /// [`WebhookRegistry::register`](crate::WebhookRegistry::register), and
    /// before every delivery — endpoints are `Deserialize`, so one built from
    /// API input never passed through the builder.
    pub fn validate(&self, policy: &EgressPolicy) -> Result<()> {
        let url = url::Url::parse(&self.url)
            .map_err(|_| WebhookError::InvalidEndpoint("URL does not parse".to_string()))?;
        policy.check_url(&url)?;
        for (name, value) in &self.headers {
            if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                || reqwest::header::HeaderValue::from_str(value).is_err()
            {
                return Err(WebhookError::InvalidEndpoint(
                    "custom header is not a valid HTTP header".to_string(),
                ));
            }
            if is_denied_header(name) {
                return Err(WebhookError::InvalidEndpoint(format!(
                    "custom header `{}` is not allowed",
                    name.to_ascii_lowercase()
                )));
            }
        }
        crate::signature::validate_secret(&self.secret)
            .map_err(|_| WebhookError::InvalidEndpoint("signing secret is too short".into()))
    }

    /// Create a new endpoint with the given URL
    pub fn new(url: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            url: url.into(),
            secret: generate_secret(),
            events: HashSet::new(),
            enabled: true,
            description: None,
            headers: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
            last_success: None,
            last_failure: None,
            failure_count: 0,
        }
    }

    /// Create a builder for custom configuration
    pub fn builder(url: impl Into<String>) -> WebhookEndpointBuilder {
        WebhookEndpointBuilder::new(url)
    }

    /// Set the signing secret
    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = secret.into();
        self
    }

    /// Subscribe to specific events
    pub fn with_events(mut self, events: Vec<&str>) -> Self {
        self.events = events.into_iter().map(String::from).collect();
        self
    }

    /// Add a single event subscription
    pub fn subscribe(&mut self, event: impl Into<String>) {
        self.events.insert(event.into());
    }

    /// Remove an event subscription
    pub fn unsubscribe(&mut self, event: &str) {
        self.events.remove(event);
    }

    /// Check if this endpoint is subscribed to an event
    pub fn is_subscribed_to(&self, event: &str) -> bool {
        // Check exact match
        if self.events.contains(event) {
            return true;
        }

        // Check wildcard subscriptions (e.g., "user.*" matches "user.created")
        for subscribed in &self.events {
            if subscribed.ends_with(".*") {
                let prefix = &subscribed[..subscribed.len() - 2];
                if event.starts_with(prefix) {
                    return true;
                }
            } else if subscribed == "*" {
                return true;
            }
        }

        false
    }

    /// Record a successful delivery
    pub fn record_success(&mut self) {
        self.last_success = Some(Utc::now());
        self.failure_count = 0;
        self.updated_at = Utc::now();
    }

    /// Record a failed delivery
    pub fn record_failure(&mut self) {
        self.last_failure = Some(Utc::now());
        self.failure_count += 1;
        self.updated_at = Utc::now();
    }

    /// Disable the endpoint
    pub fn disable(&mut self) {
        self.enabled = false;
        self.updated_at = Utc::now();
    }

    /// Enable the endpoint
    pub fn enable(&mut self) {
        self.enabled = true;
        self.failure_count = 0;
        self.updated_at = Utc::now();
    }

    /// Regenerate the signing secret
    pub fn rotate_secret(&mut self) -> String {
        self.secret = generate_secret();
        self.updated_at = Utc::now();
        self.secret.clone()
    }
}

/// Builder for WebhookEndpoint
#[derive(Debug, Clone)]
pub struct WebhookEndpointBuilder {
    endpoint: WebhookEndpoint,
}

impl WebhookEndpointBuilder {
    /// Create a new builder
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            endpoint: WebhookEndpoint::new(url),
        }
    }

    /// Set a custom ID
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.endpoint.id = id.into();
        self
    }

    /// Set the signing secret
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.endpoint.secret = secret.into();
        self
    }

    /// Subscribe to events
    pub fn events(mut self, events: Vec<&str>) -> Self {
        self.endpoint.events = events.into_iter().map(String::from).collect();
        self
    }

    /// Subscribe to all events
    pub fn all_events(mut self) -> Self {
        self.endpoint.events.insert("*".to_string());
        self
    }

    /// Set the description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.endpoint.description = Some(desc.into());
        self
    }

    /// Add a custom header
    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.endpoint.headers.insert(key.into(), value.into());
        self
    }

    /// Set enabled status
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.endpoint.enabled = enabled;
        self
    }

    /// Build the endpoint, validating it against the strict default
    /// [`EgressPolicy`] (see [`WebhookEndpoint::validate`]).
    pub fn build(self) -> Result<WebhookEndpoint> {
        self.build_with_policy(&EgressPolicy::default())
    }

    /// Build the endpoint, validating it against `policy` — e.g. one that
    /// allows loopback, for local development.
    pub fn build_with_policy(self, policy: &EgressPolicy) -> Result<WebhookEndpoint> {
        self.endpoint.validate(policy)?;
        Ok(self.endpoint)
    }
}

/// Generate a signing secret: `whsec_` + 32 bytes from the OS CSPRNG, hex.
///
/// The previous generator mixed a UUIDv4 with a timestamp; only the UUID's
/// 122 random bits were secret, and the format leaked the creation time.
fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    format!("whsec_{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "custom-secret-that-is-at-least-32-bytes";

    #[test]
    fn test_endpoint_creation() {
        let endpoint = WebhookEndpoint::new("https://example.com/webhook");

        assert!(!endpoint.id.is_empty());
        assert!(endpoint.secret.starts_with("whsec_"));
        assert!(endpoint.enabled);
        assert!(endpoint.events.is_empty());
    }

    #[test]
    fn test_generated_secret_is_32_random_bytes() {
        let a = WebhookEndpoint::new("https://example.com").secret;
        let b = WebhookEndpoint::new("https://example.com").secret;
        assert_eq!(a.len(), "whsec_".len() + 64);
        assert!(a["whsec_".len()..].chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn test_debug_redacts_secret_and_header_values() {
        let endpoint = WebhookEndpoint::builder("https://example.com/webhook")
            .secret(SECRET)
            .header("X-Api-Key", "tenant-api-key-value")
            .build()
            .unwrap();
        let dbg = format!("{endpoint:?}");
        assert!(!dbg.contains(SECRET), "{dbg}");
        assert!(!dbg.contains("tenant-api-key-value"), "{dbg}");
        assert!(dbg.contains("X-Api-Key"));
    }

    #[test]
    fn test_build_rejects_internal_and_non_https_urls() {
        for url in [
            "http://example.com/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.5/hook",
            "https://127.0.0.1/hook",
            "https://[::ffff:169.254.169.254]/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://localhost/hook",
            "not a url",
        ] {
            assert!(
                WebhookEndpoint::builder(url).build().is_err(),
                "{url} must be refused"
            );
        }
        let loopback = EgressPolicy::default().allow_insecure_loopback(true);
        assert!(
            WebhookEndpoint::builder("http://127.0.0.1:8080/hook")
                .build_with_policy(&loopback)
                .is_ok()
        );
    }

    #[test]
    fn test_build_rejects_denied_custom_headers() {
        for name in [
            "Host",
            "Metadata-Flavor",
            "Metadata",
            "X-aws-ec2-metadata-token",
            "X-aws-ec2-metadata-token-ttl-seconds",
            "Authorization",
            "Cookie",
            "Proxy-Authorization",
            "Connection",
            "Transfer-Encoding",
            "Content-Length",
            "X-Webhook-Signature",
            "X-Forwarded-For",
        ] {
            let result = WebhookEndpoint::builder("https://example.com/hook")
                .header(name, "x")
                .build();
            assert!(
                matches!(result, Err(WebhookError::InvalidEndpoint(_))),
                "{name} must be refused"
            );
        }
        assert!(
            WebhookEndpoint::builder("https://example.com/hook")
                .header("X-Custom", "bad\nvalue")
                .build()
                .is_err()
        );
    }

    #[test]
    fn test_build_rejects_short_secret() {
        assert!(
            WebhookEndpoint::builder("https://example.com/hook")
                .secret("short")
                .build()
                .is_err()
        );
    }

    #[test]
    fn test_endpoint_builder() {
        let endpoint = WebhookEndpoint::builder("https://example.com/webhook")
            .secret(SECRET)
            .events(vec!["user.created", "user.updated"])
            .description("My webhook")
            .header("X-Custom", "value")
            .build()
            .unwrap();

        assert_eq!(endpoint.secret, SECRET);
        assert!(endpoint.events.contains("user.created"));
        assert!(endpoint.events.contains("user.updated"));
        assert_eq!(endpoint.description, Some("My webhook".to_string()));
        assert_eq!(endpoint.headers.get("X-Custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_event_subscription() {
        let mut endpoint = WebhookEndpoint::new("https://example.com");

        endpoint.subscribe("user.created");
        assert!(endpoint.is_subscribed_to("user.created"));
        assert!(!endpoint.is_subscribed_to("user.deleted"));

        endpoint.unsubscribe("user.created");
        assert!(!endpoint.is_subscribed_to("user.created"));
    }

    #[test]
    fn test_wildcard_subscription() {
        let endpoint = WebhookEndpoint::builder("https://example.com")
            .events(vec!["user.*", "order.created"])
            .build()
            .unwrap();

        // Wildcard should match
        assert!(endpoint.is_subscribed_to("user.created"));
        assert!(endpoint.is_subscribed_to("user.updated"));
        assert!(endpoint.is_subscribed_to("user.deleted"));

        // Exact match
        assert!(endpoint.is_subscribed_to("order.created"));

        // No match
        assert!(!endpoint.is_subscribed_to("order.updated"));
        assert!(!endpoint.is_subscribed_to("product.created"));
    }

    #[test]
    fn test_all_events_subscription() {
        let endpoint = WebhookEndpoint::builder("https://example.com")
            .all_events()
            .build()
            .unwrap();

        assert!(endpoint.is_subscribed_to("anything"));
        assert!(endpoint.is_subscribed_to("user.created"));
        assert!(endpoint.is_subscribed_to("order.shipped"));
    }

    #[test]
    fn test_failure_tracking() {
        let mut endpoint = WebhookEndpoint::new("https://example.com");

        endpoint.record_failure();
        assert_eq!(endpoint.failure_count, 1);
        assert!(endpoint.last_failure.is_some());

        endpoint.record_failure();
        assert_eq!(endpoint.failure_count, 2);

        endpoint.record_success();
        assert_eq!(endpoint.failure_count, 0);
        assert!(endpoint.last_success.is_some());
    }

    #[test]
    fn test_secret_rotation() {
        let mut endpoint = WebhookEndpoint::new("https://example.com");
        let old_secret = endpoint.secret.clone();

        let new_secret = endpoint.rotate_secret();

        assert_ne!(old_secret, new_secret);
        assert_eq!(endpoint.secret, new_secret);
    }
}
