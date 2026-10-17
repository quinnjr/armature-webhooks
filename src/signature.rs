//! Webhook signature generation and verification
//!
//! # Wire format
//!
//! Armature signs a delivery as
//!
//! ```text
//! X-Webhook-Signature: t=<unix-seconds>,v2=<hex(HMAC(K, t || "." || body))>
//! ```
//!
//! where the MAC key `K` is **derived** from the shared secret rather than
//! being the secret itself:
//!
//! ```text
//! K = HMAC(key = "armature-webhooks/v2", msg = secret)
//! ```
//!
//! using the configured hash (SHA-256 or SHA-512) for both steps.
//!
//! The derivation is domain separation from the GitHub-style scheme
//! (`sha256=<hex(HMAC(secret, body))>`), which a receiver can opt into with
//! [`WebhookReceiver::github`](crate::WebhookReceiver::github). Under the old
//! `v1` format both schemes keyed HMAC with the raw secret, so a valid
//! `t=..,v1=` signature over `body` *was* a valid GitHub signature over the
//! body `"<t>.<body>"`, and vice versa. With a derived key, neither scheme's
//! MACs say anything about the other's: a GitHub-style signer computes
//! `HMAC(secret, ·)`, and nothing it outputs is `K` or a MAC under `K`.
//!
//! Secrets must be at least [`MIN_SECRET_LEN`] bytes.

use std::fmt;

use crate::config::SigningAlgorithm;
use crate::{Result, WebhookError};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Minimum accepted length of a webhook signing secret, in bytes.
///
/// HMAC with a short or empty key is trivially brute-forced offline from a
/// single captured delivery; 32 bytes matches the 256-bit strength of
/// HMAC-SHA256.
pub const MIN_SECRET_LEN: usize = 32;

/// Key-derivation label for the `t=..,v2=` scheme. See the module docs.
const V2_KDF_LABEL: &[u8] = b"armature-webhooks/v2";

/// Webhook signature utilities
///
/// `Debug` never prints the secret.
#[derive(Clone)]
pub struct WebhookSignature {
    secret: String,
    algorithm: SigningAlgorithm,
}

impl fmt::Debug for WebhookSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSignature")
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Reject secrets that are too short to resist offline brute force.
pub(crate) fn validate_secret(secret: &str) -> Result<()> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(WebhookError::ConfigError(format!(
            "webhook signing secret must be at least {MIN_SECRET_LEN} bytes"
        )));
    }
    Ok(())
}

impl WebhookSignature {
    /// Create a new signature utility with the given secret
    ///
    /// Uses HMAC-SHA256 by default. Use [`WebhookSignature::with_algorithm`]
    /// to select a different signing algorithm (e.g. HMAC-SHA512).
    ///
    /// # Errors
    ///
    /// [`WebhookError::ConfigError`] if the secret is shorter than
    /// [`MIN_SECRET_LEN`] bytes.
    pub fn new(secret: impl Into<String>) -> Result<Self> {
        let secret = secret.into();
        validate_secret(&secret)?;
        Ok(Self {
            secret,
            algorithm: SigningAlgorithm::HmacSha256,
        })
    }

    /// Set the signing algorithm to use for signing and verification
    pub fn with_algorithm(mut self, algorithm: SigningAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// The configured algorithm.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Generate a `t=..,v2=..` signature for the payload, timestamped now.
    pub fn sign(&self, payload: &[u8]) -> String {
        self.sign_with_timestamp(payload, &Self::current_timestamp())
    }

    /// Generate a `t=..,v2=..` signature with a specific timestamp
    pub fn sign_with_timestamp(&self, payload: &[u8], timestamp: &str) -> String {
        let signature = self.v2_mac(timestamp.as_bytes(), payload);
        format!("t={},v2={}", timestamp, signature)
    }

    /// Verify a `t=<timestamp>,v2=<hex>` signature against the payload.
    ///
    /// The timestamp must be within `tolerance_secs` of now (in either
    /// direction). Only the Armature scheme is accepted here; the timestampless
    /// GitHub-style scheme is a separate, explicit opt-in
    /// ([`WebhookSignature::verify_github`]).
    pub fn verify(&self, payload: &[u8], signature: &str, tolerance_secs: u64) -> Result<bool> {
        let parts = Self::parse_signature(signature)?;

        let timestamp: i64 = parts
            .timestamp
            .parse()
            .map_err(|_| WebhookError::TimestampInvalid("Invalid timestamp format".to_string()))?;

        let now = chrono::Utc::now().timestamp();
        let age = (now - timestamp).unsigned_abs();

        if age > tolerance_secs {
            return Err(WebhookError::TimestampInvalid(format!(
                "Timestamp too old: {} seconds (tolerance: {} seconds)",
                age, tolerance_secs
            )));
        }

        let expected = self.v2_mac(parts.timestamp.as_bytes(), payload);
        Ok(constant_time_compare(&parts.signature, &expected))
    }

    /// Verify a GitHub-style timestampless signature: `sha256=<hex>` (or
    /// `sha512=<hex>` when the algorithm is HMAC-SHA512), an HMAC over the raw
    /// body keyed with the raw secret.
    ///
    /// The prefix must match the configured algorithm. This scheme carries no
    /// timestamp, so on its own a captured delivery verifies forever; use it
    /// through a [`WebhookReceiver`](crate::WebhookReceiver) built with
    /// [`WebhookReceiver::github`](crate::WebhookReceiver::github), which adds
    /// a replay cache.
    pub fn verify_github(&self, payload: &[u8], signature: &str) -> Result<bool> {
        let prefix = match self.algorithm {
            SigningAlgorithm::HmacSha256 => "sha256=",
            SigningAlgorithm::HmacSha512 => "sha512=",
        };
        let hex_sig = signature.strip_prefix(prefix).ok_or_else(|| {
            WebhookError::SignatureInvalid(format!(
                "expected a `{prefix}<hex>` signature for the configured algorithm"
            ))
        })?;
        let expected = hmac_hex(self.algorithm, self.secret.as_bytes(), &[payload]);
        Ok(constant_time_compare(hex_sig, &expected))
    }

    /// HMAC under the derived v2 key over `timestamp || "." || payload`, fed
    /// as raw bytes (no lossy UTF-8 conversion or intermediate allocation).
    fn v2_mac(&self, timestamp: &[u8], payload: &[u8]) -> String {
        let key = derive_v2_key(self.algorithm, self.secret.as_bytes());
        hmac_hex(self.algorithm, &key, &[timestamp, b".", payload])
    }

    /// Get current Unix timestamp as string
    fn current_timestamp() -> String {
        chrono::Utc::now().timestamp().to_string()
    }

    /// Parse a signature string into components
    fn parse_signature(signature: &str) -> Result<SignatureParts> {
        let mut timestamp = None;
        let mut sig = None;

        for part in signature.split(',') {
            let mut kv = part.splitn(2, '=');
            match (kv.next(), kv.next()) {
                (Some("t"), Some(t)) => timestamp = Some(t.to_string()),
                (Some("v2"), Some(v)) => sig = Some(v.to_string()),
                _ => {}
            }
        }

        match (timestamp, sig) {
            (Some(t), Some(s)) => Ok(SignatureParts {
                timestamp: t,
                signature: s,
            }),
            _ => Err(WebhookError::SignatureInvalid(
                "Missing timestamp or v2 signature".to_string(),
            )),
        }
    }
}

/// `K = HMAC(key = V2_KDF_LABEL, msg = secret)`. The secret is the HMAC
/// *message*, never the key, so no output of a raw-secret-keyed HMAC (the
/// GitHub-style scheme) can equal `K`.
fn derive_v2_key(algorithm: SigningAlgorithm, secret: &[u8]) -> Vec<u8> {
    match algorithm {
        SigningAlgorithm::HmacSha256 => {
            let mut mac = HmacSha256::new_from_slice(V2_KDF_LABEL).expect("HMAC takes any key");
            mac.update(secret);
            mac.finalize().into_bytes().to_vec()
        }
        SigningAlgorithm::HmacSha512 => {
            let mut mac = HmacSha512::new_from_slice(V2_KDF_LABEL).expect("HMAC takes any key");
            mac.update(secret);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn hmac_hex(algorithm: SigningAlgorithm, key: &[u8], parts: &[&[u8]]) -> String {
    match algorithm {
        SigningAlgorithm::HmacSha256 => {
            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key");
            for p in parts {
                mac.update(p);
            }
            hex::encode(mac.finalize().into_bytes())
        }
        SigningAlgorithm::HmacSha512 => {
            let mut mac = HmacSha512::new_from_slice(key).expect("HMAC takes any key");
            for p in parts {
                mac.update(p);
            }
            hex::encode(mac.finalize().into_bytes())
        }
    }
}

/// Parsed signature components
struct SignatureParts {
    timestamp: String,
    signature: String,
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Header names for webhook signatures
#[allow(dead_code)]
pub mod headers {
    /// The signature header name
    pub const SIGNATURE: &str = "X-Webhook-Signature";

    /// GitHub's signature header (GitHub mode only)
    pub const SIGNATURE_GITHUB: &str = "X-Hub-Signature-256";

    /// GitHub's SHA-512 signature header name (GitHub mode with HMAC-SHA512)
    pub const SIGNATURE_GITHUB_512: &str = "X-Hub-Signature-512";

    /// GitHub's delivery id header (GitHub mode only)
    pub const GITHUB_DELIVERY: &str = "X-GitHub-Delivery";

    /// Timestamp header (if sent separately)
    pub const TIMESTAMP: &str = "X-Webhook-Timestamp";

    /// Webhook ID header
    pub const WEBHOOK_ID: &str = "X-Webhook-Id";

    /// Event type header
    pub const EVENT_TYPE: &str = "X-Webhook-Event";
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

    fn signer() -> WebhookSignature {
        WebhookSignature::new(SECRET).unwrap()
    }

    #[test]
    fn test_sign_and_verify() {
        let payload = b"Hello, World!";
        let signature = signer().sign(payload);
        assert!(signature.starts_with("t="));
        assert!(signature.contains(",v2="));
        assert!(signer().verify(payload, &signature, 300).unwrap());
    }

    #[test]
    fn test_short_and_empty_secrets_are_rejected() {
        assert!(matches!(
            WebhookSignature::new(""),
            Err(WebhookError::ConfigError(_))
        ));
        assert!(WebhookSignature::new("x".repeat(MIN_SECRET_LEN - 1)).is_err());
        assert!(WebhookSignature::new("x".repeat(MIN_SECRET_LEN)).is_ok());
    }

    #[test]
    fn test_debug_redacts_secret() {
        let dbg = format!("{:?}", signer());
        assert!(!dbg.contains(SECRET), "{dbg}");
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn test_sign_with_timestamp_is_deterministic() {
        let sig1 = signer().sign_with_timestamp(b"test payload", "1234567890");
        let sig2 = signer().sign_with_timestamp(b"test payload", "1234567890");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_verify_invalid_signature() {
        assert!(signer().verify(b"test payload", "invalid", 300).is_err());
    }

    #[test]
    fn test_old_v1_format_is_rejected() {
        let ts = chrono::Utc::now().timestamp().to_string();
        let v1 = format!("t={ts},v1={}", "a".repeat(64));
        assert!(signer().verify(b"x", &v1, 300).is_err());
    }

    #[test]
    fn test_verify_wrong_secret() {
        let other = WebhookSignature::new("another-secret-that-is-32-bytes-long!!").unwrap();
        let signature = signer().sign(b"test payload");
        assert!(!other.verify(b"test payload", &signature, 300).unwrap());
    }

    #[test]
    fn test_verify_expired_timestamp() {
        let old_timestamp = (chrono::Utc::now().timestamp() - 1000).to_string();
        let signature = signer().sign_with_timestamp(b"test payload", &old_timestamp);
        assert!(signer().verify(b"test payload", &signature, 60).is_err());
    }

    #[test]
    fn test_sha512_algorithm_selection_produces_sha512_signature() {
        let sha256_signer = signer();
        let sha512_signer = signer().with_algorithm(SigningAlgorithm::HmacSha512);

        let sha256_sig = sha256_signer.sign_with_timestamp(b"p", "1234567890");
        let sha512_sig = sha512_signer.sign_with_timestamp(b"p", "1234567890");
        assert_ne!(sha256_sig, sha512_sig);
        assert_eq!(sha512_sig.split("v2=").nth(1).unwrap().len(), 128);
        assert_eq!(sha256_sig.split("v2=").nth(1).unwrap().len(), 64);

        let live = sha512_signer.sign(b"p");
        assert!(sha512_signer.verify(b"p", &live, 300).unwrap());
        assert!(!sha256_signer.verify(b"p", &live, 300).unwrap());
    }

    fn github_sig(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn test_verify_github_style_signature() {
        let payload = b"{\"action\":\"opened\"}";
        let sig = github_sig(SECRET, payload);
        assert!(signer().verify_github(payload, &sig).unwrap());
        assert!(
            !signer()
                .verify_github(b"{\"action\":\"closed\"}", &sig)
                .unwrap()
        );
    }

    #[test]
    fn test_github_scheme_is_not_accepted_by_the_timestamped_verifier() {
        // The timestamped verifier used to accept `sha256=` as a silent
        // fallback, with no replay protection and ignoring the algorithm.
        let sig = github_sig(SECRET, b"body");
        assert!(signer().verify(b"body", &sig, 300).is_err());
    }

    #[test]
    fn test_github_verifier_honours_the_configured_algorithm() {
        let sha512 = signer().with_algorithm(SigningAlgorithm::HmacSha512);
        let sig256 = github_sig(SECRET, b"body");
        assert!(sha512.verify_github(b"body", &sig256).is_err());

        let mut mac = HmacSha512::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(b"body");
        let sig512 = format!("sha512={}", hex::encode(mac.finalize().into_bytes()));
        assert!(sha512.verify_github(b"body", &sig512).unwrap());
    }

    #[test]
    fn test_schemes_are_domain_separated() {
        // Under v1, `t=T,v1=HMAC(secret, "T." || body)` was byte-for-byte the
        // GitHub signature of the body `"T." || body`. With the derived key the
        // two never coincide, in either direction.
        let ts = chrono::Utc::now().timestamp().to_string();
        let body = b"{\"a\":1}";
        let v2 = signer().sign_with_timestamp(body, &ts);
        let v2_hex = v2.split("v2=").nth(1).unwrap();

        let mut confused_body = format!("{ts}.").into_bytes();
        confused_body.extend_from_slice(body);
        assert!(
            !signer()
                .verify_github(&confused_body, &format!("sha256={v2_hex}"))
                .unwrap()
        );

        let gh = github_sig(SECRET, &confused_body);
        let gh_hex = gh.strip_prefix("sha256=").unwrap();
        assert!(
            !signer()
                .verify(body, &format!("t={ts},v2={gh_hex}"), 300)
                .unwrap()
        );
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("abc", "abc"));
        assert!(!constant_time_compare("abc", "abd"));
        assert!(!constant_time_compare("abc", "ab"));
        assert!(!constant_time_compare("", "a"));
    }
}
