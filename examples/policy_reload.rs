//! # Example 02 — Production Policy Reload
//!
//! Demonstrates how to construct the correlation API from the upstream Palisade
//! defaults, then reload a modified policy through the production-safe reload
//! path.

use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;

fn main() {
    let mut initial = PolicyConfig::default();
    let api = CorrelationApi::new_production(&mut initial)
        .expect("initial policy should construct a production API");

    println!(
        "mimikatz.exe suspicious? {}",
        api.is_suspicious_process("mimikatz.exe")
    );
    println!(
        "custom-loader suspicious before reload? {}",
        api.is_suspicious_process("custom-loader")
    );

    let mut reload = PolicyConfig::default();
    let mut suspicious_processes = reload.deception.suspicious_processes.to_vec();
    suspicious_processes.push("custom-loader".to_string());
    reload.deception.suspicious_processes = suspicious_processes.into_boxed_slice();
    reload.response.cooldown_secs = 120;

    api.reload_policy_production(&mut reload)
        .expect("reload should harden and apply");

    println!(
        "custom-loader suspicious after reload? {}",
        api.is_suspicious_process("custom-loader")
    );
    println!(
        "max_events_per_source after reload hardening: {}",
        reload.scoring.max_events_in_memory
    );
}
