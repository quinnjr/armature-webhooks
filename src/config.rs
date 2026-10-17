//! Configuration for webhook client

use crate::RetryPolicy;
use armature_http_client::egress::EgressPolicy;
use std::time::Duration;

/// Configuration for the webhook client
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Default timeout for webhook requests
    pub timeout: Duration,

    /// User-Agent header for outgoing requests
    pub user_agent: String,

    /// Default retry policy
    pub retry_policy: RetryPolicy,

    /// Whether to verify TLS certificates. Only exists with the
    /// `dangerous-insecure-tls` feature; without it, certificates are always
    /// verified.
    #[cfg(feature = "dangerous-insecure-tls")]
    pub verify_ssl: bool,

    /// Which endpoint URLs deliveries may go to.
    ///
    /// The default is the strict [`EgressPolicy`]: https only, and no
    /// loopback, private, link-local (cloud metadata), or other
    /// special-purpose address — checked on the URL, and again on every DNS
    /// answer at connect time, so a name that resolves (or re-resolves) to an
    /// internal address is refused. Redirects are never followed and proxies
    /// are never used. For local development against a stub on localhost, use
    /// `EgressPolicy::default().allow_insecure_loopback(true)`.
    pub egress: EgressPolicy,

    /// Record (up to [`max_response_body_size`](Self::max_response_body_size)
    /// bytes of) each receiver's response body on the
    /// [`WebhookDelivery`](crate::WebhookDelivery). **Default: `false`.**
    ///
    /// Off by default because the response body is chosen by whoever controls
    /// the endpoint; storing it and showing it back (a delivery log in an
    /// admin UI) turns any request the sender can be induced to make into a
    /// readable response.
    pub store_response_bodies: bool,

    /// Maximum payload size in bytes
    pub max_payload_size: usize,

    /// Timestamp tolerance for signature verification (in seconds)
    pub timestamp_tolerance: u64,

    /// Default signing algorithm
    pub signing_algorithm: SigningAlgorithm,

    /// Maximum number of endpoint deliveries a single
    /// [`dispatch`](crate::WebhookClient::dispatch) runs concurrently.
    ///
    /// Fan-out used to be unbounded: an account with 5,000 subscribed
    /// endpoints opened 5,000 sockets at once, which exhausts file descriptors
    /// and ephemeral ports on the sender long before it inconveniences any
    /// receiver. A value of `0` is treated as `1`.
    pub max_concurrent_deliveries: usize,

    /// Maximum number of response bytes recorded on a
    /// [`WebhookDelivery`](crate::WebhookDelivery), per attempt, when
    /// [`store_response_bodies`](Self::store_response_bodies) is enabled.
    ///
    /// The response body of a webhook is diagnostic only, but it is written
    /// into a delivery record that is often persisted. Reading it in full let
    /// a hostile or merely broken receiver stream an unbounded body back and
    /// exhaust the sender's memory, so the read stops at this many bytes and
    /// the rest of the body is discarded unread.
    pub max_response_body_size: usize,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            user_agent: format!("Armature-Webhooks/{}", env!("CARGO_PKG_VERSION")),
            retry_policy: RetryPolicy::default(),
            #[cfg(feature = "dangerous-insecure-tls")]
            verify_ssl: true,
            egress: EgressPolicy::default(),
            store_response_bodies: false,
            max_payload_size: 1024 * 1024, // 1MB
            timestamp_tolerance: 300,      // 5 minutes
            signing_algorithm: SigningAlgorithm::HmacSha256,
            max_concurrent_deliveries: 32,
            max_response_body_size: 8 * 1024, // 8 KiB
        }
    }
}

impl WebhookConfig {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for custom configuration
    pub fn builder() -> WebhookConfigBuilder {
        WebhookConfigBuilder::new()
    }
}

/// Builder for WebhookConfig
#[derive(Debug, Clone, Default)]
pub struct WebhookConfigBuilder {
    config: WebhookConfig,
}

impl WebhookConfigBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            config: WebhookConfig::default(),
        }
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set the timeout in seconds
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.config.timeout = Duration::from_secs(secs);
        self
    }

    /// Set the User-Agent header
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    /// Set the retry policy
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.config.retry_policy = policy;
        self
    }

    /// Disable retries
    pub fn no_retries(mut self) -> Self {
        self.config.retry_policy = RetryPolicy::none();
        self
    }

    /// Set TLS certificate verification. Requires the
    /// `dangerous-insecure-tls` feature; disabling verification logs a
    /// warning when the client is created.
    #[cfg(feature = "dangerous-insecure-tls")]
    pub fn verify_ssl(mut self, verify: bool) -> Self {
        self.config.verify_ssl = verify;
        self
    }

    /// Set the egress (SSRF) policy for deliveries.
    pub fn egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.config.egress = policy;
        self
    }

    /// Record receivers' response bodies on deliveries (default: off).
    pub fn store_response_bodies(mut self, store: bool) -> Self {
        self.config.store_response_bodies = store;
        self
    }

    /// Set maximum payload size
    pub fn max_payload_size(mut self, size: usize) -> Self {
        self.config.max_payload_size = size;
        self
    }

    /// Set timestamp tolerance for signature verification
    pub fn timestamp_tolerance(mut self, seconds: u64) -> Self {
        self.config.timestamp_tolerance = seconds;
        self
    }

    /// Set the signing algorithm
    pub fn signing_algorithm(mut self, algorithm: SigningAlgorithm) -> Self {
        self.config.signing_algorithm = algorithm;
        self
    }

    /// Set the maximum number of concurrent deliveries per dispatch
    pub fn max_concurrent_deliveries(mut self, max: usize) -> Self {
        self.config.max_concurrent_deliveries = max;
        self
    }

    /// Set the maximum number of response bytes recorded per attempt
    pub fn max_response_body_size(mut self, size: usize) -> Self {
        self.config.max_response_body_size = size;
        self
    }

    /// Build the configuration
    pub fn build(self) -> WebhookConfig {
        self.config
    }
}

/// Supported signing algorithms
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningAlgorithm {
    /// HMAC-SHA256 (default, most common)
    #[default]
    HmacSha256,

    /// HMAC-SHA512 (more secure)
    HmacSha512,
}

impl SigningAlgorithm {
    /// Get the algorithm name for headers
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::HmacSha256 => "sha256",
            Self::HmacSha512 => "sha512",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WebhookConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_payload_size, 1024 * 1024);
        assert!(!config.store_response_bodies);
        assert!(!config.egress.allows_http());
        assert!(!config.egress.allows_loopback());
    }

    #[test]
    fn test_builder() {
        let config = WebhookConfig::builder()
            .timeout_secs(60)
            .max_payload_size(2048)
            .store_response_bodies(true)
            .build();

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_payload_size, 2048);
        assert!(config.store_response_bodies);
    }

    #[cfg(feature = "dangerous-insecure-tls")]
    #[test]
    fn test_builder_verify_ssl() {
        let config = WebhookConfig::builder().verify_ssl(false).build();
        assert!(!config.verify_ssl);
    }

    #[test]
    fn test_signing_algorithm() {
        assert_eq!(SigningAlgorithm::HmacSha256.header_value(), "sha256");
        assert_eq!(SigningAlgorithm::HmacSha512.header_value(), "sha512");
    }
}
