# armature-webhooks

Webhook handling for the Armature framework.

## Features

- **Signature Verification** - HMAC-SHA256/SHA512 signatures (`t=<ts>,v2=<hex>`, derived key), replay cache, opt-in GitHub-style mode (`WebhookReceiver::github`)
- **SSRF Protection** - Deliveries go only to public `https` endpoints (`EgressPolicy`), never follow redirects or use proxies
- **Retry Support** - Automatic delivery retries with configurable backoff
- **Event Registry** - Subscribe endpoints to specific event types and dispatch to all of them

## Installation

```toml
[dependencies]
armature-webhooks = "0.6"
```

Signing secrets must be at least 32 bytes (`MIN_SECRET_LEN`); constructors that take a
secret return `Result`. Disabling TLS verification requires the
`dangerous-insecure-tls` feature and must never be used in production.

## Quick Start

### Receiving webhooks

```rust
use armature_webhooks::WebhookReceiver;

// At least 32 bytes, from your secret store; errors otherwise.
let receiver = WebhookReceiver::new(std::env::var("WEBHOOK_SECRET")?)?;

// Create a handler that only processes "order.*" events
let handler = receiver.handler("order.*", |event| {
    match event.event.as_str() {
        "order.created" => {
            // process_order(event.data)
        }
        _ => {}
    }
    Ok(())
});

// In your request handling code, verify + dispatch a raw request body
// and its `X-Webhook-Signature` header value:
let handled = handler.handle(payload_bytes, signature_header)?;
```

### Sending webhooks

```rust
use armature_webhooks::{WebhookClient, WebhookConfig, WebhookPayload};

let client = WebhookClient::new(WebhookConfig::default());

let payload = WebhookPayload::new("user.created")
    .with_data(serde_json::json!({
        "user_id": "123",
        "email": "user@example.com"
    }));

// Sign and send with a specific secret (at least 32 bytes)
let secret = std::env::var("WEBHOOK_SECRET")?;
client.send_with_secret("https://example.com/webhook", payload, Some(&secret)).await?;
```

## License

MIT OR Apache-2.0
