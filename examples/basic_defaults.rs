//! # Example 01 — Basic Defaults & Correlation
//!
//! Demonstrates the default Palisade policy flow for the correlation crate:
//! validate upstream policy, harden it for the fixed-capacity runtime, ingest a
//! small attacker-like event sequence, and inspect the final decision using
//! fixed-size output buffers.

use palisade_config::{PolicyApi, PolicyConfig};
use palisade_correlation::CorrelationApi;
use std::net::IpAddr;

fn main() {
    let mut policy = PolicyConfig::default();
    PolicyApi::new()
        .validate(&policy)
        .expect("default policy must validate");

    let api = CorrelationApi::new_production(&mut policy)
        .expect("default policy should be hardenable for production");

    let source_ip: IpAddr = "192.168.1.100".parse().expect("valid IP");

    api.observe_rapid_enumeration(source_ip, "session-1", 50, 30, 70.0)
        .expect("rapid enumeration should ingest");
    api.observe_artifact_access(
        source_ip,
        "session-1",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    )
    .expect("artifact access should ingest");
    api.observe_suspicious_process(source_ip, "session-1", "mimikatz.exe", 1337, 95.0)
        .expect("suspicious process should ingest");

    let mut patterns = [0u16; CorrelationApi::MAX_PATTERN_CODES];
    let pattern_count = api.write_last_pattern_codes(&mut patterns);

    let mut source = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
    let source_written = api.write_last_source_ip(&mut source);
    let source_text =
        std::str::from_utf8(&source[..source_written]).expect("source IP must remain valid UTF-8");

    println!("=== Correlation Result ===");
    println!("source_ip         : {source_text}");
    println!("score             : {:.2}", api.last_score());
    println!("severity_code     : {}", api.last_severity_code());
    println!("action_code       : {}", api.last_action_code());
    println!("kill_chain_stage  : {}", api.last_kill_chain_stage_code());
    println!("pattern_count     : {}", pattern_count);
    println!("patterns          : {:?}", &patterns[..pattern_count]);
    println!("tracked_sources   : {}", api.tracked_sources());
    println!("total_events      : {}", api.total_events_processed());
}
