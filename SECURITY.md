# Security Policy

## Abstract

This document defines the security posture, threat model, implemented controls,
operational assumptions, and disclosure expectations for
`palisade-correlation`.

The crate is designed as the correlation component of the Palisade 2.0
ecosystem. It depends on `palisade-config` for policy admission and on
`palisade-errors` for the shared failure contract. It should therefore be
understood as one hardened stage in a broader defensive pipeline, not as a
standalone security boundary.

## Supported Versions

Security fixes are applied to the latest released version only.

## Reporting Vulnerabilities

Do not report suspected vulnerabilities through public issues before a private
disclosure path has been used.

Send reports to:

- `strukturaenterprise@gmail.com`

Include:

- affected crate version
- Rust toolchain and target platform
- whether the issue is reachable from attacker-controlled event input, policy input, or both
- whether the issue occurs at startup, reload time, or steady-state processing
- reproduction steps
- impact assessment

## Scope

This policy covers the crate's behavior in the following areas:

- event admission and validation through the public correlation API
- bounded per-source runtime state
- pattern inference and score calculation
- response-decision resolution under cooldown and kill-limit pressure
- policy conversion from `palisade-config::PolicyConfig`
- failure behavior through `palisade-errors::AgentError`
- optional encrypted audit logging for correlation-owned records
- fuzzing and validation of the public API surface
- internal module separation for policy conversion, runtime state, timing, and
  event admission

This policy does not cover:

- configuration or policy admission rules owned by `palisade-config`
- encrypted error logging internals owned by `palisade-errors`
- privileged response execution outside the crate boundary
- host hardening, kernel compromise, or network containment

## Threat Model

`palisade-correlation` assumes attackers may:

1. submit malformed or adversarial event inputs repeatedly
2. cause high event volume or noisy probing patterns
3. influence or replace policy inputs before they reach the crate
4. compare error outcomes and operational timing at the public surface
5. attempt to exploit silent degradation in response logic

The crate is designed to reduce unsafe behavior under those conditions by
keeping runtime state bounded, rejecting unsupported policy shapes, and forcing
response bookkeeping to remain explicit.

## Current Guarantees

### 1. Public API Reduction

The crate exports exactly one public operational type: `CorrelationApi`.
Internal engine types, event models, and pattern state remain crate-private.

### 2. Bounded Runtime State

Tracked-source state, history windows, pattern buffers, and suspicious-policy
sets are fixed-capacity. Steady-state event processing is intended to avoid
heap allocation.

### 3. Fail-Closed Policy Conversion

Unsupported custom response conditions are rejected. Policies that exceed the
crate's fixed-capacity assumptions, including oversized event-retention limits,
are rejected rather than silently approximated.

The only explicit production-time normalization is opt-in through
`CorrelationApi::harden_policy(...)`, `new_production(...)`, and
`reload_policy_production(...)`. That path caps
`scoring.max_events_in_memory` at `CorrelationApi::MAX_EVENTS_PER_SOURCE` so
the upstream default `PolicyConfig` can be admitted into this crate's
fixed-capacity runtime.

### 4. Explicit Response Bookkeeping

Cooldown and response bookkeeping do not silently succeed for untracked
sources. Pruning requires an explicit non-zero age.

### 5. Shared Ecosystem Error Contract

Fallible operations return `palisade-errors::AgentError`, preserving the same
failure contract used across the other Palisade 2.0 components.

### 6. Delegated Encrypted Audit Persistence

When `feature = "log"` is enabled, this crate persists correlation-owned audit
records by delegating to `palisade-errors::AgentError::log(...)`.

That means:

- this crate does not maintain an independent logging cipher implementation
- the effective cryptographic backend includes `crypto_bastion 0.4.0` through
  `palisade-errors`
- enabled audit writes fail closed when encrypted persistence cannot complete

### 7. Startup-Time Allocation Exception

The crate intentionally uses a boxed lock and a larger-stack initialization
thread during engine construction. This exists to avoid stack exhaustion during
startup. It is not the steady-state runtime model.

### 8. Role-Oriented Internal Structure

The private code layout is intentionally split so that distinct concerns remain
reviewable in isolation:

- `api.rs` for the operational surface
- `events.rs` for input admission
- `policy.rs` for runtime policy conversion and response evaluation
- `runtime.rs` for fixed-capacity state
- `timing.rs` for timing-floor and clock behavior
- `patterns.rs` for detection heuristics

This does not make the crate safe by itself, but it reduces the amount of
security-sensitive behavior hidden behind any one file or module.

## Operational Requirements

Operators should treat the following as mandatory in high-risk deployments:

- validate or admit policy through `palisade-config` before constructing
  `CorrelationApi`
- prefer `CorrelationApi::new_production(...)` and
  `reload_policy_production(...)` when starting from upstream defaults or
  mutable `PolicyConfig` values
- treat `CorrelationApi::new(...)` failure as a hard startup failure
- do not ignore failures from `reload_policy(...)`,
  `record_response_for_source(...)`, or `prune_stale_sources(...)`
- use an absolute owner-controlled audit path when `feature = "log"` is
  enabled
- keep privileged action execution outside this crate and behind separate
  authorization controls

Strongly recommended controls:

- fuzz smoke the public API on release candidates
- review policy changes with the same scrutiny applied to code changes
- benchmark timing floors and event throughput on the deployment hardware class
- review which correlation success categories are persisted before enabling
  observation or response-action audit logging
- pin the Rust toolchain and keep release verification tied to the checked-in
  lockfile
- keep incident-response logic separate from the correlation decision engine

## Known Limitations

### 1. This Crate Does Not Replace `palisade-config`

Policy parsing, file admission, and policy serialization are not the
responsibility of this crate. Compatibility depends on the admitted
`PolicyConfig` contract provided by `palisade-config`.

### 2. This Crate Does Not Replace `palisade-errors`

The failure contract, timing-normalized error behavior, and optional encrypted
logging live in `palisade-errors`. This crate composes with that contract; it
does not duplicate it. Correlation-side audit logging follows the same rule.

### 3. Timing Discipline Is a Mitigation, Not a Proof

Public-path timing floors reduce coarse distinguishability. They do not
eliminate scheduler effects, pre-error work, or microarchitectural leakage.

### 4. Startup Is Not Allocation-Free

The crate preserves a startup-time boxed engine and larger-stack construction
path. Production claims should describe steady-state boundedness accurately
rather than overstating complete allocation elimination.

## Verification

Recommended release validation:

```bash
cargo generate-lockfile
cargo fmt --all
cargo test
cargo test --features log
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml
```

Recommended adversarial check:

```bash
cargo +nightly fuzz run public_api -- -max_total_time=20
```

Recommended supply-chain check:

```bash
cargo audit
cargo deny check
```

## Release Controls

The repository is expected to carry the following release-hardening assets:

- `rust-toolchain.toml` to pin the expected Rust toolchain
- `Cargo.lock` to make verification and release review dependency-explicit
- `deny.toml` to define dependency license, advisory, and source policy
- `.github/workflows/ci.yml` for locked verification gates
- `.github/workflows/security.yml` for audit, dependency-policy, and fuzz-smoke gates

These controls reduce accidental drift between local verification, CI, and
published release artifacts. They do not remove the need for human review.

## Change-Sensitive Areas

Changes to the following files or modules deserve elevated review:

- `src/api.rs`
- `src/engine.rs`
- `src/events.rs`
- `src/policy.rs`
- `src/runtime.rs`
- `src/timing.rs`
- `src/patterns.rs`
- `src/error_codes.rs`
- any dependency or feature changes involving `palisade-config` or
  `palisade-errors`

## Disclosure Policy

Please allow time for triage and coordinated remediation before public
disclosure. Reports that include concrete reproductions and deployment context
are substantially easier to assess and prioritize.
