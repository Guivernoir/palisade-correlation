//! # Example 03 — Runtime Hot Paths
//!
//! Demonstrates fixed-buffer readback and steady-state event processing using
//! the public API. This example uses `CorrelationApi::new(...)` after explicit
//! hardening so the caller can control timing-floor behavior directly.

use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;
use std::net::{IpAddr, Ipv4Addr};

const SESSIONS: [&str; 4] = ["session-a", "session-b", "session-c", "session-d"];

fn main() {
    let mut policy = PolicyConfig::default();
    CorrelationApi::harden_policy(&mut policy).expect("policy should harden");
    let api = CorrelationApi::new(&policy).expect("api should construct");

    for (index, session_id) in SESSIONS.iter().enumerate() {
        let source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (index + 10) as u8));
        api.observe_network_probe(source_ip, session_id, "22,80,443", "TCP", 60.0)
            .expect("network probe should ingest");
        api.observe_authentication_failure(source_ip, session_id, "admin", "ssh", 70.0)
            .expect("authentication failure should ingest");
    }

    let mut patterns = [0u16; CorrelationApi::MAX_PATTERN_CODES];
    let pattern_count = api.write_last_pattern_codes(&mut patterns);

    let mut source = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
    let source_written = api.write_last_source_ip(&mut source);
    let source_text =
        std::str::from_utf8(&source[..source_written]).expect("source IP should be UTF-8");

    println!("=== Hot-Path Readback ===");
    println!("has_last_result   : {}", api.has_last_result());
    println!("last_source_ip    : {source_text}");
    println!("last_score        : {:.2}", api.last_score());
    println!("last_action_code  : {}", api.last_action_code());
    println!("pattern_count     : {}", pattern_count);
    println!("patterns          : {:?}", &patterns[..pattern_count]);
}
