#![cfg(feature = "log")]

use palisade_config::PolicyConfig;
use palisade_correlation::CorrelationApi;
use std::net::IpAddr;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn absolute_log_path_persists_audit_records() {
    let mut policy = PolicyConfig::default();
    let dir = tempdir().expect("temporary directory should be created");
    let log_path = dir.path().join("correlation.audit");
    let source_ip: IpAddr = "192.168.1.240".parse().expect("valid IP");

    let api = CorrelationApi::new_production(&mut policy)
        .expect("production API should construct")
        .with_log_path(&log_path)
        .log_errors(true)
        .log_observations(true)
        .log_policy_updates(true)
        .log_response_actions(true);

    api.observe_artifact_access(
        source_ip,
        "session-logged",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    )
    .expect("successful observation should be logged");

    let initial_len = std::fs::metadata(&log_path)
        .expect("encrypted audit file should exist after the first write")
        .len();
    assert!(initial_len > 0);

    let mut reload = PolicyConfig::default();
    reload.response.cooldown_secs = 120;
    api.reload_policy_production(&mut reload)
        .expect("policy reload should also be logged");

    let reloaded_len = std::fs::metadata(&log_path)
        .expect("encrypted audit file should still exist after reload logging")
        .len();
    assert!(reloaded_len >= initial_len);
}

#[test]
fn relative_log_paths_fail_closed() {
    let relative_path = Path::new("relative-correlation-audit.log");
    let _ = std::fs::remove_file(relative_path);

    let mut policy = PolicyConfig::default();
    let source_ip: IpAddr = "192.168.1.241".parse().expect("valid IP");
    let api = CorrelationApi::new_production(&mut policy)
        .expect("production API should construct")
        .with_log_path(relative_path)
        .log_observations(true);

    let result = api.observe_artifact_access(
        source_ip,
        "session-relative",
        "fake-aws-credentials",
        "aws-prod-decoy",
        100.0,
    );

    let error = result.expect_err("relative log paths should fail closed");
    assert_eq!(error.to_string(), "Audit operation failed");
    assert!(!relative_path.exists());
}
