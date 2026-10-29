# Changelog — `armature-webhooks`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

## [0.7.0] - 2026-10-29

### Changed

- Requires `armature-core` 0.12 (was `0.11`).
- The `signature_verify` fuzz target compiles again (it used a moved value).
- CI: actions pinned to commit SHAs, a least-privilege `GITHUB_TOKEN`, and Dependabot for actions.

## [0.6.0] - 2026-10-17

### Security

- **Webhook delivery SSRF (C2).** Every delivery now goes through an
  `EgressPolicy` (from `armature-http-client`): endpoint URLs must be `https`
  and may not target loopback, private, link-local/cloud-metadata, or other
  special-purpose addresses — checked on the URL and again on every DNS answer
  when a connection is opened (re-resolved per new connection, connection
  pinned to the vetted addresses). Redirects are never followed and system
  proxies are never used. A policy refusal fails the delivery permanently
  without retries.
- Custom endpoint headers are validated against a deny-list (`Host`,
  `Authorization`, `Cookie`, `Proxy-*`, `Metadata*`, `X-aws-ec2-metadata-token*`,
  `X-Google-Metadata-Request`, hop-by-hop and framing headers, `Content-*`,
  `X-Webhook-*`, `X-Hub-Signature*`, `Forwarded`/`X-Forwarded-*`) in
  `WebhookEndpointBuilder::build`, `WebhookRegistry::register`/`update`, and
  before every delivery.
- Receivers' response bodies are no longer stored on `WebhookDelivery` by
  default (`WebhookConfig::store_response_bodies`, opt-in, still capped by
  `max_response_body_size`).
- **Receiver hardening (M1).** The GitHub-style timestampless `sha256=` scheme
  is no longer a silent fallback of every verifier: it is a separate,
  receiver-scoped mode (`WebhookReceiver::github`) that honours the configured
  algorithm (`sha512=` for HMAC-SHA512). Receivers keep a replay cache keyed by
  the verified signature and the delivery id (`X-Webhook-Id` /
  `X-GitHub-Delivery`) for the tolerance window, failing closed when full.
- Signing secrets shorter than 32 bytes (including empty) are rejected;
  generated secrets are 32 bytes from the OS CSPRNG (`whsec_` + 64 hex chars)
  instead of a UUID plus a timestamp.
- `Debug` for `WebhookSignature`, `WebhookReceiver` and `WebhookEndpoint` no
  longer prints the secret (or custom header values) (H27).

### Changed

- **Breaking:** signature format is now `t=<ts>,v2=<hex>` with the MAC keyed by
  `HMAC(key = "armature-webhooks/v2", msg = secret)` (domain separation from the
  GitHub scheme). Migration: upgrade senders and receivers together;
  third-party receivers must derive the key as documented in `signature.rs`.
- **Breaking:** `WebhookSignature::new`, `WebhookReceiver::new`/`from_config`
  return `Result`; `WebhookSignature::verify` no longer accepts `sha256=`
  (use `verify_github` / `WebhookReceiver::github`).
- **Breaking:** `WebhookEndpointBuilder::build` returns `Result` (use
  `build_with_policy` for dev loopback targets); `WebhookRegistry::register`
  returns `Result<String>`.
- **Breaking:** `WebhookConfig::verify_ssl` / `verify_ssl()` exist only with the
  new `dangerous-insecure-tls` feature and log a warning when disabled.
- **Breaking:** `WebhookConfig` gains `egress` and `store_response_bodies`;
  `WebhookError` is `#[non_exhaustive]` with new `ReplayDetected`,
  `ReplayCacheFull`, `EgressRefused` and `InvalidEndpoint` variants.
- New dependencies: `armature-http-client` (egress guard), `getrandom`.

### Added

- `is_denied_header`, `MIN_SECRET_LEN`, `EgressPolicy` re-export,
  `WebhookRegistry::with_egress_policy`, `WebhookEndpoint::validate`,
  `WebhookReceiver::{github, with_algorithm, with_github_replay_window,
  with_replay_cache_capacity}`.

## [0.5.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `tokio` 1.52 → 1.53, `uuid` 1.23 → 1.26, `tokio` 1.52 → 1.53.

## [0.4.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.

## [0.3.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.
