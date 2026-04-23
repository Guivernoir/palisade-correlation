# palisade-correlation

Security-conscious correlation for honeypot, deception, and high-scrutiny
detection deployments.

[![Crates.io](https://img.shields.io/crates/v/palisade-correlation.svg)](https://crates.io/crates/palisade-correlation)
[![Documentation](https://docs.rs/palisade-correlation/badge.svg)](https://docs.rs/palisade-correlation)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Abstract

`palisade-correlation` is the correlation component of the Palisade 2.0
ecosystem. It is designed to sit beside `palisade-config` and
`palisade-errors`, not to replace them. The crate accepts admitted policy input
from `palisade-config`, processes attacker-facing event observations through a
single hardened operational API, and returns failures through the
`palisade-errors::AgentError` contract.

The design target is the narrower class of environments in which correlation
logic itself becomes part of a defensive surface: honeypots, deception
infrastructure, exposed telemetry agents, and other systems operating under
adversarial observation. In that setting, the crate prioritizes bounded state,
restricted public surface, predictable behavior, and fail-closed policy
handling over feature breadth or ergonomic generality.

## Positioning

This crate is a good fit when the following properties matter:

- correlation decisions must remain operationally legible and bounded
- public-path event handling should avoid heap allocation after initialization
- unsupported policy shapes should be rejected instead of silently degraded
- the public API should remain narrow enough for direct review
- the crate must compose cleanly with `palisade-config` and `palisade-errors`

It is a poor fit when the following priorities dominate:

- generic analytics or SIEM-style correlation across unbounded schemas
- convenience-first builder APIs and wide public object graphs
- permissive acceptance of arbitrary custom condition extensions
- opaque runtime machinery that trades auditability for flexibility

## Public Interface

The operational public surface is intentionally centered on one type:

- `CorrelationApi`

That API is the supported entry point for:

- event ingestion
- response bookkeeping
- policy reload
- last-result inspection
- optional encrypted audit logging

The intended ecosystem flow is:

1. admit or validate policy through `palisade-config`
2. construct `CorrelationApi` from `PolicyConfig`
3. process observations through inherent methods on `CorrelationApi`
4. handle failures through `palisade-errors::AgentError`

For high-risk production, the recommended constructor is
`CorrelationApi::new_production(&mut policy)`. It explicitly hardens the
upstream `PolicyConfig` shape into this crate's fixed-capacity runtime
expectations while still failing closed on unsupported features such as custom
response conditions.

## Internal Layout

The private crate layout now follows the same role-oriented structure used by
the other Palisade components:

- `api.rs` owns the single public operational surface
- `events.rs` owns borrowed input validation and event normalization
- `policy.rs` owns runtime policy conversion and response evaluation
- `runtime.rs` owns fixed-capacity state and last-outcome retention
- `timing.rs` owns timing-floor and clock helpers
- `patterns.rs` owns fixed-code pattern inference
- `matching.rs`, `failures.rs`, and `error_codes.rs` remain small private
  support modules

This keeps the external contract narrow while making internal review more
local: policy logic, runtime state, timing behavior, and input validation are
now separated rather than cohabiting one large implementation file.

## Ecosystem Compatibility

This crate follows the same ecosystem rules as the other Palisade 2.0
components, while keeping a role-specific implementation:

- `palisade-config` remains the source of configuration and policy admission
- `palisade-errors` remains the shared failure and timing-normalization contract
- `palisade-correlation` remains the bounded scoring and response-decision layer

The crates are therefore aligned by contract rather than merged by
responsibility. They share design constraints, error discipline, and public API
reduction while still owning different parts of the defensive pipeline.

## Security Properties

### 1. Single Public Operational Surface

`CorrelationApi` is the only public type exported by the crate. Internal state
tracking, event normalization, pattern inference, and policy conversion remain
crate-private.

### 2. Bounded Runtime Behavior

Per-source state, pattern retention, suspicious-process lists, and result
buffers use fixed-capacity structures. This keeps the steady-state runtime
bounded and reviewable.

### 3. Borrowed Ingestion Model

Event methods accept borrowed inputs and caller-provided buffers rather than
exposing heap-owning public event models or allocation-heavy result types.

### 4. Fail-Closed Policy Handling

Unsupported custom response conditions and oversized in-memory event retention
are rejected at admission time. This crate does not silently reinterpret unsafe
or unsupported policy shapes.

The one explicit production-time normalization is available only through the
production helpers:

- `CorrelationApi::harden_policy(&mut policy)`
- `CorrelationApi::new_production(&mut policy)`
- `CorrelationApi::reload_policy_production(&mut policy)`

That normalization caps `scoring.max_events_in_memory` at
`CorrelationApi::MAX_EVENTS_PER_SOURCE` so the current upstream
`PolicyConfig::default()` from `palisade-config` can be used safely with this
crate's fixed-capacity runtime.

### 5. Explicit Startup Exception

The engine is constructed behind a boxed lock on a larger-stack initialization
thread. This is an intentional startup-time concession to avoid stack
exhaustion during construction. The steady-state event path remains
fixed-capacity and allocation-free.

### 6. Encrypted Log Persistence

When `feature = "log"` is enabled, this crate does not implement a second
logging cipher stack of its own. Instead, it persists selected audit records by
delegating to `palisade-errors::AgentError::log(...)`.

That matters for both reviewability and ecosystem consistency:

- encrypted persistence follows the same hardened sink already used by
  `palisade-errors`
- the effective cryptographic backend includes `crypto_bastion 0.4.0` through
  that dependency
- audit persistence failures fail closed at the correlation API boundary

The available audit categories follow the same explicit builder-style pattern
used by the sibling Palisade components:

- `log_errors(true)`
- `log_observations(true)`
- `log_policy_updates(true)`
- `log_response_actions(true)`

## Installation

```toml
[dependencies]
palisade-correlation = "2.0.0"
```

For ecosystem-aligned use:

```toml
[dependencies]
palisade-config = "2.0.0"
palisade-errors = "2.0.0"
palisade-correlation = "2.0.0"
```

Enable encrypted audit persistence:

```toml
[dependencies]
palisade-config = { version = "2.0.0", features = ["log"] }
palisade-errors = { version = "2.0.0", features = ["log"] }
palisade-correlation = { version = "2.0.0", features = ["log"] }
```

## Quick Start

### 1. Validate Policy Through `palisade-config`

```rust
use palisade_config::{PolicyApi, PolicyConfig};
use palisade_correlation::CorrelationApi;

let mut policy = PolicyConfig::default();

PolicyApi::new().validate(&policy).unwrap();
let api = CorrelationApi::new_production(&mut policy).unwrap();
```

### 2. Observe Events

```rust
use std::net::IpAddr;

let source: IpAddr = "192.168.1.100".parse().unwrap();

api.observe_artifact_access(
    source,
    "session-1",
    "fake-aws-credentials",
    "aws-prod-decoy",
    100.0,
)
.unwrap();

assert!(api.last_score() > 0.0);
```

### 3. Inspect the Last Decision

```rust
assert!(api.has_last_result());
assert_eq!(api.last_action_code(), CorrelationApi::ACTION_ALERT);
```

### 4. Enable Encrypted Audit Logging

```rust,no_run
use std::path::Path;

let audit_path = Path::new("/var/log/palisade/correlation.audit");

let api = CorrelationApi::new_production(&mut policy)
    .unwrap()
    .with_log_path(audit_path)
    .log_errors(true)
    .log_observations(true)
    .log_policy_updates(true)
    .log_response_actions(true);
```

This keeps correlation-side audit persistence aligned with the other Palisade
components: the correlation crate decides what to record, while
`palisade-errors` owns the encrypted append-only sink.

## Verification Workflow

Recommended local verification:

```bash
cargo generate-lockfile
cargo fmt --all
cargo test
cargo test --features log
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml
```

Recommended supply-chain checks:

```bash
cargo audit
cargo deny check
```

## Release Discipline

The repository now includes the same kind of release controls expected of a
Palisade production component:

- `rust-toolchain.toml` pins the expected Rust toolchain and required developer
  components
- `Cargo.lock` is intended to be checked in and regenerated intentionally
- `deny.toml` defines dependency-source, advisory, and license policy
- `.github/workflows/ci.yml` enforces formatting, tests, feature checks, and
  clippy with `--locked`
- `.github/workflows/security.yml` enforces advisory, dependency-policy, and
  fuzz-smoke checks

These controls do not make a deployment secure on their own, but they narrow
the gap between what is reviewed locally and what is executed in CI and release
flows.

## Production Checklist

Before trusting a release in a high-risk deployment, the following should all
be true:

- `Cargo.lock` was regenerated intentionally and reviewed
- `cargo test`, `cargo test --features log`, and `cargo clippy --all-targets --all-features -- -D warnings` pass on the release commit
- `cargo audit` and `cargo deny check` pass on the release commit
- the audit log path is absolute, owner-controlled, and covered by retention policy
- `PolicyApi::validate(...)` or equivalent admission is performed before constructing `CorrelationApi`
- destructive response execution remains outside this crate and behind separate authorization controls
- timing and throughput have been benchmarked on the actual deployment hardware class

Short fuzz smoke:

```bash
cargo +nightly fuzz run public_api -- -max_total_time=3
```

## Limitations

The current crate should be adopted with the following boundaries in mind:

- it does not execute privileged response actions itself
- it does not accept arbitrary custom response conditions
- it does not eliminate all startup-time allocation
- it depends on `palisade-config` for policy admission and `palisade-errors`
  for shared failure behavior
- encrypted audit persistence is delegated to `palisade-errors` rather than
  implemented independently here
- it is a bounded correlation component, not a full detection platform

## Related Documents

- [Security Policy](SECURITY.md)
- [Fuzz Harness](fuzz/)
