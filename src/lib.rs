//! Webhook Orchestration for Armature
//!
//! This crate provides comprehensive webhook support for the Armature framework,
//! including both sending outgoing webhooks and receiving incoming webhooks.
//!
//! # Features
//!
//! - **Outgoing Webhooks**: Send HTTP callbacks to registered endpoints
//! - **Incoming Webhooks**: Receive and verify webhooks from external services
//! - **Signature Verification**: HMAC-SHA256/SHA512 signing and verification
//! - **Automatic Retries**: Configurable retry policies with exponential backoff
//! - **Event System**: Subscribe endpoints to specific event types
//! - **Delivery Tracking**: Monitor delivery status and per-endpoint success/failure counters
//!
//! # Example: Sending Webhooks
//!
//! ```rust,no_run
//! use armature_webhooks::{WebhookClient, WebhookConfig, WebhookPayload};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = WebhookClient::new(WebhookConfig::default());
//!
//!     let payload = WebhookPayload::new("user.created")
//!         .with_data(serde_json::json!({
//!             "user_id": "123",
//!             "email": "user@example.com"
//!         }));
//!
//!     client.send("https://example.com/webhook", payload).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Example: Receiving Webhooks
//!
//! ```rust,no_run
//! use armature_webhooks::WebhookReceiver;
//!
//! // Secrets must be at least 32 bytes.
//! let receiver = WebhookReceiver::new("whsec_0123456789abcdef0123456789abcdef")?;
//!
//! // Verify incoming webhook (a verified delivery is remembered, so the same
//! // request cannot be accepted twice)
//! let payload_bytes = b"webhook payload";
//! let signature_header = "t=1234567890,v2=abc123...";
//!
//! let is_valid = receiver.verify(payload_bytes, signature_header);
//! # Ok::<(), armature_webhooks::WebhookError>(())
//! ```
//!
//! # Security
//!
//! - **Outgoing requests are SSRF-guarded.** Endpoint URLs must be `https`
//!   and may not point (literally, or via DNS at connect time) at loopback,
//!   private, link-local/metadata or other special-purpose addresses;
//!   redirects are never followed; proxies are never used; cloud-metadata,
//!   credential and hop-by-hop headers cannot be set as custom endpoint
//!   headers; and receivers' response bodies are not recorded unless
//!   [`WebhookConfig::store_response_bodies`] is enabled. Configure with
//!   [`WebhookConfig::egress`] (an
//!   [`EgressPolicy`](armature_http_client::egress::EgressPolicy)).
//! - **Signatures** use `t=<ts>,v2=<hex>` with a key derived from the secret
//!   (see [`WebhookSignature`]); GitHub-style `sha256=` verification is a
//!   separate receiver mode ([`WebhookReceiver::github`]).
//!
//! # Example: Webhook Registry
//!
//! ```rust,no_run
//! use armature_webhooks::{WebhookRegistry, WebhookEndpoint};
//!
//! let registry = WebhookRegistry::new();
//!
//! // Register an endpoint for specific events (validated on registration)
//! registry.register(WebhookEndpoint::new("https://api.example.com/webhooks")
//!     .with_events(vec!["order.created", "order.updated"]))?;
//!
//! // Get all endpoints subscribed to an event
//! let endpoints = registry.get_endpoints_for_event("order.created");
//! # Ok::<(), armature_webhooks::WebhookError>(())
//! ```

mod client;
mod config;
mod endpoint;
mod error;
mod payload;
mod receiver;
mod registry;
mod retry;
mod signature;

pub use client::WebhookClient;
pub use config::{SigningAlgorithm, WebhookConfig, WebhookConfigBuilder};
pub use endpoint::{WebhookEndpoint, WebhookEndpointBuilder, is_denied_header};
pub use error::WebhookError;
pub use payload::{WebhookDelivery, WebhookDeliveryStatus, WebhookPayload};
pub use receiver::WebhookReceiver;
pub use registry::WebhookRegistry;
pub use retry::{RetryPolicy, RetryResult};
pub use signature::{MIN_SECRET_LEN, WebhookSignature};

/// Re-exported so endpoint egress policy can be configured without a direct
/// `armature-http-client` dependency.
pub use armature_http_client::egress::EgressPolicy;

/// Result type for webhook operations
pub type Result<T> = std::result::Result<T, WebhookError>;
