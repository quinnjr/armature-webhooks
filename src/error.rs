//! Error types for webhook operations

use thiserror::Error;

/// Errors that can occur during webhook operations
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum WebhookError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Invalid URL
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Signature missing from request
    #[error("Signature missing from request")]
    SignatureMissing,

    /// Timestamp validation failed
    #[error("Timestamp validation failed: {0}")]
    TimestampInvalid(String),

    /// Payload serialization/deserialization failed
    #[error("Payload error: {0}")]
    PayloadError(String),

    /// Delivery failed after all retries
    #[error("Delivery failed after {attempts} attempts: {message}")]
    DeliveryFailed { attempts: u32, message: String },

    /// Endpoint not found
    #[error("Endpoint not found: {0}")]
    EndpointNotFound(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded for endpoint: {0}")]
    RateLimitExceeded(String),

    /// Timeout error
    #[error("Request timed out after {0} seconds")]
    Timeout(u64),

    /// The same delivery (signature or delivery id) was already accepted.
    #[error("Replay detected: this webhook delivery was already accepted")]
    ReplayDetected,

    /// The replay cache is full of unexpired entries; the delivery is refused
    /// rather than accepted without a replay check.
    #[error("Replay cache is full; delivery refused")]
    ReplayCacheFull,

    /// The endpoint URL (or a DNS answer for it) was refused by the egress
    /// policy.
    #[error("{0}")]
    EgressRefused(#[from] armature_http_client::egress::EgressError),

    /// The endpoint is invalid (bad URL, forbidden or malformed custom header,
    /// short secret).
    #[error("Invalid webhook endpoint: {0}")]
    InvalidEndpoint(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<serde_json::Error> for WebhookError {
    fn from(err: serde_json::Error) -> Self {
        WebhookError::PayloadError(err.to_string())
    }
}
