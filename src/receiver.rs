//! Webhook receiver for handling incoming webhooks

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::SigningAlgorithm;
use crate::signature::headers;
use crate::{Result, WebhookConfig, WebhookError, WebhookPayload, WebhookSignature};

/// Default number of recently-seen deliveries remembered for replay detection.
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 100_000;

/// Default replay window for the timestampless GitHub scheme: 24 hours.
pub const DEFAULT_GITHUB_REPLAY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Which signature scheme a receiver accepts. Exactly one per receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// Armature's `t=<ts>,v2=<hex>` in `X-Webhook-Signature`.
    Armature,
    /// GitHub's `sha256=<hex>` in `X-Hub-Signature-256` (`sha512=` in
    /// `X-Hub-Signature-512` with HMAC-SHA512).
    GitHub,
}

/// Remembers verified deliveries so the same request cannot be accepted twice.
#[derive(Debug, Default)]
struct ReplayCache {
    seen: HashMap<String, Instant>,
}

impl ReplayCache {
    /// Record `keys`, failing if any of them was already recorded and has not
    /// expired. Fails closed when the cache is full of live entries.
    fn check_and_record(&mut self, keys: &[String], ttl: Duration, capacity: usize) -> Result<()> {
        let now = Instant::now();
        if keys
            .iter()
            .any(|k| self.seen.get(k).is_some_and(|expiry| *expiry > now))
        {
            return Err(WebhookError::ReplayDetected);
        }
        if self.seen.len() + keys.len() > capacity {
            self.seen.retain(|_, expiry| *expiry > now);
            if self.seen.len() + keys.len() > capacity {
                tracing::warn!(
                    capacity,
                    "webhook replay cache is full of live entries; refusing delivery"
                );
                return Err(WebhookError::ReplayCacheFull);
            }
        }
        for k in keys {
            self.seen.insert(k.clone(), now + ttl);
        }
        Ok(())
    }
}

/// Receiver for incoming webhooks
///
/// Every successful verification is recorded in a replay cache shared by all
/// clones of the receiver, so a captured request cannot be accepted twice:
/// the cache is keyed by the verified signature (which binds the timestamp
/// and body) and, when the sender supplies one, by the delivery id
/// (`X-Webhook-Id`, or `X-GitHub-Delivery` in GitHub mode). Entries live for
/// the timestamp tolerance window on both sides of now (Armature scheme) or
/// the GitHub replay window (GitHub scheme).
///
/// `Debug` never prints the secret.
#[derive(Clone)]
pub struct WebhookReceiver {
    signature: WebhookSignature,
    scheme: Scheme,
    timestamp_tolerance: u64,
    github_replay_window: Duration,
    replay_capacity: usize,
    replay: Arc<Mutex<ReplayCache>>,
}

impl fmt::Debug for WebhookReceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookReceiver")
            .field("signature", &self.signature)
            .field("scheme", &self.scheme)
            .field("timestamp_tolerance", &self.timestamp_tolerance)
            .field("github_replay_window", &self.github_replay_window)
            .field("replay_capacity", &self.replay_capacity)
            .finish_non_exhaustive()
    }
}

impl WebhookReceiver {
    /// Create a receiver for Armature-signed (`t=..,v2=..`) webhooks.
    ///
    /// Uses [`WebhookConfig::default`] for the timestamp tolerance and signing
    /// algorithm; see [`WebhookReceiver::from_config`].
    ///
    /// # Errors
    ///
    /// [`WebhookError::ConfigError`] if the secret is shorter than
    /// [`MIN_SECRET_LEN`](crate::MIN_SECRET_LEN) bytes.
    pub fn new(secret: impl Into<String>) -> Result<Self> {
        Self::from_config(secret, &WebhookConfig::default())
    }

    /// Create a receiver for Armature-signed webhooks from a
    /// [`WebhookConfig`], so its `timestamp_tolerance` and `signing_algorithm`
    /// are honored.
    pub fn from_config(secret: impl Into<String>, config: &WebhookConfig) -> Result<Self> {
        Ok(Self {
            signature: WebhookSignature::new(secret)?.with_algorithm(config.signing_algorithm),
            scheme: Scheme::Armature,
            timestamp_tolerance: config.timestamp_tolerance,
            github_replay_window: DEFAULT_GITHUB_REPLAY_WINDOW,
            replay_capacity: DEFAULT_REPLAY_CACHE_CAPACITY,
            replay: Arc::new(Mutex::new(ReplayCache::default())),
        })
    }

    /// Create a receiver for GitHub-style webhooks (`X-Hub-Signature-256:
    /// sha256=<hex>`), and *only* those.
    ///
    /// This scheme has no timestamp, so the only replay protection is this
    /// receiver's replay cache, which remembers deliveries for
    /// [`with_github_replay_window`](Self::with_github_replay_window)
    /// (24 hours by default) and is per-process. A request captured and
    /// replayed after the window, or against another replica, verifies. Use it
    /// for providers that only offer this scheme, with a secret dedicated to
    /// that provider.
    pub fn github(secret: impl Into<String>) -> Result<Self> {
        let mut receiver = Self::new(secret)?;
        receiver.scheme = Scheme::GitHub;
        Ok(receiver)
    }

    /// Select the HMAC algorithm (in GitHub mode, `HmacSha512` expects
    /// `sha512=` in `X-Hub-Signature-512`).
    pub fn with_algorithm(mut self, algorithm: SigningAlgorithm) -> Self {
        self.signature = self.signature.with_algorithm(algorithm);
        self
    }

    /// Set the timestamp tolerance in seconds
    pub fn with_tolerance(mut self, seconds: u64) -> Self {
        self.timestamp_tolerance = seconds;
        self
    }

    /// How long a GitHub-scheme delivery is remembered for replay detection.
    pub fn with_github_replay_window(mut self, window: Duration) -> Self {
        self.github_replay_window = window;
        self
    }

    /// Maximum number of live replay-cache entries. When the cache is full of
    /// unexpired entries, deliveries are refused
    /// ([`WebhookError::ReplayCacheFull`]) rather than accepted unchecked.
    pub fn with_replay_cache_capacity(mut self, capacity: usize) -> Self {
        self.replay_capacity = capacity;
        self
    }

    /// Verify an incoming webhook signature and record it for replay
    /// detection.
    ///
    /// Returns `Ok(false)` for a well-formed but wrong signature, and
    /// `Err(WebhookError::ReplayDetected)` for a signature that already
    /// verified once.
    pub fn verify(&self, payload: &[u8], signature: &str) -> Result<bool> {
        self.verify_with_id(payload, signature, None)
    }

    fn verify_with_id(
        &self,
        payload: &[u8],
        signature: &str,
        delivery_id: Option<&str>,
    ) -> Result<bool> {
        let (valid, ttl) = match self.scheme {
            Scheme::Armature => (
                self.signature
                    .verify(payload, signature, self.timestamp_tolerance)?,
                // A timestamp is accepted up to `tolerance` in the past *or*
                // the future, so a signature can stay valid for 2x tolerance.
                Duration::from_secs(self.timestamp_tolerance.saturating_mul(2)),
            ),
            Scheme::GitHub => (
                self.signature.verify_github(payload, signature)?,
                self.github_replay_window,
            ),
        };
        if !valid {
            return Ok(false);
        }

        let mut keys = vec![format!("sig:{signature}")];
        if let Some(id) = delivery_id.filter(|id| !id.is_empty()) {
            keys.push(format!("id:{id}"));
        }
        self.replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_and_record(&keys, ttl, self.replay_capacity)?;
        Ok(true)
    }

    /// Verify and parse an incoming webhook
    pub fn receive(&self, payload: &[u8], signature: &str) -> Result<WebhookPayload> {
        if !self.verify(payload, signature)? {
            return Err(WebhookError::SignatureInvalid(
                "Signature verification failed".to_string(),
            ));
        }
        serde_json::from_slice(payload).map_err(|e| WebhookError::PayloadError(e.to_string()))
    }

    /// Verify signature from HTTP headers (matched case-insensitively).
    ///
    /// An Armature receiver reads only `X-Webhook-Signature` (and the
    /// delivery id from `X-Webhook-Id`); a GitHub receiver reads only
    /// `X-Hub-Signature-256` (`X-Hub-Signature-512` for HMAC-SHA512) and
    /// `X-GitHub-Delivery`. A header for the other scheme is ignored, so a
    /// receiver can never be steered into a scheme it was not built for.
    pub fn verify_from_headers(
        &self,
        payload: &[u8],
        headers: &HashMap<String, String>,
    ) -> Result<bool> {
        let lower: HashMap<String, &String> =
            headers.iter().map(|(k, v)| (k.to_lowercase(), v)).collect();

        let (sig_header, id_header) = match self.scheme {
            Scheme::Armature => (headers::SIGNATURE, headers::WEBHOOK_ID),
            Scheme::GitHub => match self.signature.algorithm() {
                SigningAlgorithm::HmacSha512 => {
                    (headers::SIGNATURE_GITHUB_512, headers::GITHUB_DELIVERY)
                }
                _ => (headers::SIGNATURE_GITHUB, headers::GITHUB_DELIVERY),
            },
        };

        let signature = lower
            .get(&sig_header.to_ascii_lowercase())
            .copied()
            .ok_or(WebhookError::SignatureMissing)?;
        let id = lower
            .get(&id_header.to_ascii_lowercase())
            .map(|s| s.as_str());

        self.verify_with_id(payload, signature, id)
    }

    /// Receive and parse webhook from HTTP headers and body
    pub fn receive_from_request(
        &self,
        payload: &[u8],
        headers: &HashMap<String, String>,
    ) -> Result<WebhookPayload> {
        if !self.verify_from_headers(payload, headers)? {
            return Err(WebhookError::SignatureInvalid(
                "Signature verification failed".to_string(),
            ));
        }
        serde_json::from_slice(payload).map_err(|e| WebhookError::PayloadError(e.to_string()))
    }

    /// Create a handler for specific event types
    pub fn handler<F>(&self, event_filter: &str, callback: F) -> WebhookHandler<F>
    where
        F: Fn(WebhookPayload) -> Result<()>,
    {
        WebhookHandler {
            receiver: self.clone(),
            event_filter: event_filter.to_string(),
            callback,
        }
    }
}

/// A webhook handler that filters and processes specific events
pub struct WebhookHandler<F>
where
    F: Fn(WebhookPayload) -> Result<()>,
{
    receiver: WebhookReceiver,
    event_filter: String,
    callback: F,
}

impl<F> WebhookHandler<F>
where
    F: Fn(WebhookPayload) -> Result<()>,
{
    /// Handle an incoming webhook request
    pub fn handle(&self, payload: &[u8], signature: &str) -> Result<bool> {
        let webhook = self.receiver.receive(payload, signature)?;
        if !self.matches_event(&webhook.event) {
            return Ok(false);
        }
        (self.callback)(webhook)?;
        Ok(true)
    }

    /// Check if an event matches the filter
    fn matches_event(&self, event: &str) -> bool {
        if self.event_filter == "*" {
            return true;
        }

        if self.event_filter.ends_with(".*") {
            let prefix = &self.event_filter[..self.event_filter.len() - 2];
            return event.starts_with(prefix);
        }

        self.event_filter == event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{KeyInit, Mac};

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

    fn receiver() -> WebhookReceiver {
        WebhookReceiver::new(SECRET).unwrap()
    }

    fn signer() -> WebhookSignature {
        WebhookSignature::new(SECRET).unwrap()
    }

    fn github_sig(body: &[u8]) -> String {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn test_receiver_creation() {
        assert_eq!(receiver().timestamp_tolerance, 300);
        assert_eq!(receiver().with_tolerance(60).timestamp_tolerance, 60);
    }

    #[test]
    fn test_short_secret_is_rejected() {
        assert!(WebhookReceiver::new("").is_err());
        assert!(WebhookReceiver::new("short").is_err());
        assert!(WebhookReceiver::github("short").is_err());
    }

    #[test]
    fn test_debug_redacts_secret() {
        let dbg = format!("{:?}", receiver());
        assert!(!dbg.contains(SECRET), "{dbg}");
    }

    #[test]
    fn test_verify_valid_signature() {
        let signature = signer().sign(b"test payload");
        assert!(receiver().verify(b"test payload", &signature).unwrap());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let wrong = WebhookSignature::new("wrong-secret-that-is-at-least-32-bytes").unwrap();
        let signature = wrong.sign(b"test payload");
        assert!(!receiver().verify(b"test payload", &signature).unwrap());
    }

    #[test]
    fn test_replayed_signature_is_rejected() {
        let r = receiver();
        let signature = signer().sign(b"payload");
        assert!(r.verify(b"payload", &signature).unwrap());
        // The same captured request, again — and via a clone, which shares
        // the cache.
        assert!(matches!(
            r.clone().verify(b"payload", &signature),
            Err(WebhookError::ReplayDetected)
        ));
    }

    #[test]
    fn test_replayed_delivery_id_is_rejected_even_with_a_fresh_signature() {
        let r = receiver();
        let mut headers = HashMap::new();
        headers.insert("X-Webhook-Id".to_string(), "dlv_1".to_string());
        headers.insert("X-Webhook-Signature".to_string(), signer().sign(b"p"));
        assert!(r.verify_from_headers(b"p", &headers).unwrap());

        let ts = (chrono::Utc::now().timestamp() - 1).to_string();
        headers.insert(
            "X-Webhook-Signature".to_string(),
            signer().sign_with_timestamp(b"p", &ts),
        );
        assert!(matches!(
            r.verify_from_headers(b"p", &headers),
            Err(WebhookError::ReplayDetected)
        ));
    }

    #[test]
    fn test_full_replay_cache_fails_closed() {
        let r = receiver().with_replay_cache_capacity(1);
        assert!(r.verify(b"a", &signer().sign(b"a")).unwrap());
        assert!(matches!(
            r.verify(b"b", &signer().sign(b"b")),
            Err(WebhookError::ReplayCacheFull)
        ));
    }

    #[test]
    fn test_receive_and_parse() {
        let webhook =
            WebhookPayload::new("test.event").with_data(serde_json::json!({"key": "value"}));
        let payload_bytes = webhook.to_bytes().unwrap();
        let signature = signer().sign(&payload_bytes);
        let received = receiver().receive(&payload_bytes, &signature).unwrap();
        assert_eq!(received.event, "test.event");
    }

    #[test]
    fn test_verify_from_headers_mixed_case() {
        let mut headers = HashMap::new();
        headers.insert("x-webhook-Signature".to_string(), signer().sign(b"p"));
        assert!(receiver().verify_from_headers(b"p", &headers).unwrap());
    }

    #[test]
    fn test_default_receiver_ignores_github_header() {
        // The GitHub scheme used to be accepted by every receiver, as a
        // silent timestampless fallback.
        let mut headers = HashMap::new();
        headers.insert("X-Hub-Signature-256".to_string(), github_sig(b"p"));
        assert!(matches!(
            receiver().verify_from_headers(b"p", &headers),
            Err(WebhookError::SignatureMissing)
        ));
        assert!(receiver().verify(b"p", &github_sig(b"p")).is_err());
    }

    #[test]
    fn test_github_receiver_accepts_only_github_scheme() {
        let r = WebhookReceiver::github(SECRET).unwrap();
        let body = b"{\"action\":\"opened\"}";
        let mut headers = HashMap::new();
        headers.insert("X-Hub-Signature-256".to_string(), github_sig(body));
        headers.insert("X-GitHub-Delivery".to_string(), "abc".to_string());
        assert!(r.verify_from_headers(body, &headers).unwrap());
        // Replay of the same delivery is refused.
        assert!(matches!(
            r.verify_from_headers(body, &headers),
            Err(WebhookError::ReplayDetected)
        ));

        // An Armature signature is not accepted by a GitHub receiver.
        let r = WebhookReceiver::github(SECRET).unwrap();
        let mut headers = HashMap::new();
        headers.insert("X-Webhook-Signature".to_string(), signer().sign(body));
        assert!(matches!(
            r.verify_from_headers(body, &headers),
            Err(WebhookError::SignatureMissing)
        ));
    }

    #[test]
    fn test_from_config_threads_timestamp_tolerance() {
        let config = crate::WebhookConfig::builder()
            .timestamp_tolerance(60)
            .build();
        let receiver = WebhookReceiver::from_config(SECRET, &config).unwrap();
        assert_eq!(receiver.timestamp_tolerance, 60);
    }

    #[test]
    fn test_verify_missing_signature() {
        let headers = HashMap::new();
        assert!(matches!(
            receiver().verify_from_headers(b"payload", &headers),
            Err(WebhookError::SignatureMissing)
        ));
    }

    #[test]
    fn test_handler_event_filter() {
        let handler = receiver().handler("user.*", |_| Ok(()));
        assert!(handler.matches_event("user.created"));
        assert!(handler.matches_event("user.deleted"));
        assert!(!handler.matches_event("order.created"));
    }

    #[test]
    fn test_handler_all_events() {
        let handler = receiver().handler("*", |_| Ok(()));
        assert!(handler.matches_event("anything"));
    }

    #[test]
    fn test_handler_exact_match() {
        let handler = receiver().handler("user.created", |_| Ok(()));
        assert!(handler.matches_event("user.created"));
        assert!(!handler.matches_event("user.updated"));
    }
}
