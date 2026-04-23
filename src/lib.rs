//! # Palisade Correlation
//!
//! Security-conscious correlation for honeypot and deception deployments.
//!
//! ## Public Interface
//!
//! The crate exports exactly one public operational type: [`CorrelationApi`].
//!
//! Its inherent methods are the supported entry points for:
//!
//! - event ingestion
//! - policy reload
//! - response bookkeeping
//! - result inspection
//! - optional encrypted audit logging when `feature = "log"` is enabled
//!
//! The crate interoperates directly with the other Palisade 2.0 components:
//!
//! - `palisade-config` provides the admitted [`palisade_config::PolicyConfig`]
//!   consumed by `CorrelationApi::new(...)` and
//!   `CorrelationApi::new_production(...)`
//! - `palisade-errors` provides the [`palisade_errors::AgentError`] returned by
//!   fallible operations and the shared encrypted audit sink used by the
//!   optional `log` feature
//!
//! Everything else remains crate-private implementation detail.
//!
//! ## Core Security Properties
//!
//! - fixed-capacity internal state for deterministic runtime bounds
//! - borrowed event inputs rather than heap-owning public models
//! - caller-provided output buffers for variable-length readback
//! - fail-closed policy conversion for unsupported shapes
//! - startup-only allocation exception with allocation-free steady-state event paths
//! - delegated encrypted audit persistence through `palisade-errors`
//!
//! ## Example
//!
//! ```rust,no_run
//! use palisade_config::{PolicyApi, PolicyConfig};
//! use palisade_correlation::CorrelationApi;
//! use std::net::IpAddr;
//!
//! let mut policy = PolicyConfig::default();
//! PolicyApi::new().validate(&policy).unwrap();
//!
//! let api = CorrelationApi::new_production(&mut policy).unwrap();
//!
//! api.observe_artifact_access(
//!     "192.168.1.100".parse::<IpAddr>().unwrap(),
//!     "session-1",
//!     "fake-aws-credentials",
//!     "aws-prod-decoy",
//!     100.0,
//! )
//! .unwrap();
//!
//! assert!(api.last_score() > 0.0);
//! assert_eq!(api.last_action_code(), CorrelationApi::ACTION_ALERT);
//! ```

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::clone_on_ref_ptr)]
#![deny(unsafe_code)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::result_large_err)]

mod api;
mod engine;
mod error_codes;
mod events;
mod failures;
mod matching;
mod patterns;
mod policy;
mod runtime;
mod timing;

pub use api::CorrelationApi;
