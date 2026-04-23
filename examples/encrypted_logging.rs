//! # Example 05 — Encrypted Audit Logging
//!
//! Demonstrates delegated encrypted audit persistence through
//! `palisade-errors::AgentError::log(...)` by enabling the correlation crate's
//! `log` feature.

use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;
use std::net::IpAddr;

fn main() {
    let mut policy = PolicyConfig::default();
    let log_path = std::env::temp_dir().join("palisade-correlation.audit");
    let _ = std::fs::remove_file(&log_path);

    let api = CorrelationApi::new_production(&mut policy)
        .expect("production API should construct")
        .with_log_path(&log_path)
        .log_errors(true)
        .log_observations(true)
        .log_policy_updates(true)
        .log_response_actions(true);

    let source_ip: IpAddr = "192.168.1.250".parse().expect("valid IP");

    api.observe_artifact_access(
        source_ip,
        "session-logged",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    )
    .expect("successful observation should be logged");

    let _ = api.observe_artifact_access(
        source_ip,
        "",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    );

    println!("encrypted audit log: {}", log_path.display());
}
