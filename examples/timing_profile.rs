//! # Example 04 — Timing Floor Profile
//!
//! Demonstrates the effect of applying an explicit timing floor to the public
//! correlation API. `new_production(...)` already applies the default floor for
//! production use; this example is meant for inspection and tuning.

use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;
use std::net::IpAddr;
use std::time::Instant;

fn main() {
    let mut policy = PolicyConfig::default();
    CorrelationApi::harden_policy(&mut policy).expect("policy should harden");

    let source_ip: IpAddr = "192.168.1.200".parse().expect("valid IP");

    let intrinsic = CorrelationApi::new(&policy).expect("api should construct");
    let started = Instant::now();
    intrinsic
        .observe_custom_signal(source_ip, "session-intrinsic", "probe", 50.0)
        .expect("intrinsic call should succeed");
    let intrinsic_elapsed = started.elapsed();

    let normalized = CorrelationApi::new(&policy)
        .expect("api should construct")
        .with_timing_floor(CorrelationApi::DEFAULT_TIMING_FLOOR);
    let started = Instant::now();
    normalized
        .observe_custom_signal(source_ip, "session-normalized", "probe", 50.0)
        .expect("normalized call should succeed");
    let normalized_elapsed = started.elapsed();

    println!("=== Timing Profile ===");
    println!(
        "default timing floor : {:?}",
        CorrelationApi::DEFAULT_TIMING_FLOOR
    );
    println!("intrinsic elapsed    : {:?}", intrinsic_elapsed);
    println!("normalized elapsed   : {:?}", normalized_elapsed);
}
