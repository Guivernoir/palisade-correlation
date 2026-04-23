use palisade_config::{PolicyApi, PolicyConfig};
use palisade_correlation::CorrelationApi;
use std::net::{IpAddr, Ipv4Addr};

fn production_api() -> CorrelationApi<'static> {
    let mut policy = PolicyConfig::default();
    PolicyApi::new()
        .validate(&policy)
        .expect("default policy should validate through palisade-config");

    CorrelationApi::new_production(&mut policy)
        .expect("default policy should construct a production correlation api")
}

fn source_ip(index: usize) -> IpAddr {
    let third_octet = (index / 250) as u8;
    let fourth_octet = ((index % 250) + 1) as u8;
    IpAddr::V4(Ipv4Addr::new(10, 0, third_octet, fourth_octet))
}

#[test]
fn production_defaults_exercise_public_result_buffers() {
    let api = production_api();
    let source_ip = source_ip(1);

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

    assert!(api.has_last_result());
    assert_eq!(api.total_events_processed(), 3);
    assert_eq!(api.tracked_sources(), 1);
    assert!(api.last_score().is_finite());
    assert!(api.last_pattern_count() > 0);
    assert_eq!(api.write_last_action_script_path(&mut []), 0);

    let mut pattern_codes = [0u16; CorrelationApi::MAX_PATTERN_CODES];
    let pattern_count = api.write_last_pattern_codes(&mut pattern_codes);
    assert_eq!(pattern_count, api.last_pattern_count());

    let mut source_out = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
    let source_len = api.write_last_source_ip(&mut source_out);
    let source_text = std::str::from_utf8(&source_out[..source_len])
        .expect("source IP should remain valid UTF-8");
    assert_eq!(source_text, "10.0.0.2");
}

#[test]
fn reload_policy_production_updates_suspicious_process_matching() {
    let mut initial = PolicyConfig::default();
    PolicyApi::new()
        .validate(&initial)
        .expect("initial policy should validate through palisade-config");

    let api = CorrelationApi::new_production(&mut initial)
        .expect("initial policy should construct a production correlation api");
    assert!(!api.is_suspicious_process("palisade-integration-loader"));

    let mut reload = PolicyConfig::default();
    let mut suspicious_processes = reload.deception.suspicious_processes.to_vec();
    suspicious_processes.push("palisade-integration-loader".to_string());
    reload.deception.suspicious_processes = suspicious_processes.into_boxed_slice();
    reload.response.cooldown_secs = 120;

    api.reload_policy_production(&mut reload)
        .expect("reload should harden and apply");

    assert!(api.is_suspicious_process("PALISADE-INTEGRATION-LOADER"));
    assert!(
        reload.scoring.max_events_in_memory <= CorrelationApi::MAX_EVENTS_PER_SOURCE,
        "production reload should keep the policy within the fixed-capacity runtime bound"
    );
}

#[test]
fn tracked_sources_remain_bounded_at_the_public_limit() {
    let api = production_api();

    for index in 0..=CorrelationApi::MAX_TRACKED_SOURCES {
        let source_ip = source_ip(index);
        api.observe_custom_signal(source_ip, "scan-session", "probe.wave", 55.0)
            .expect("custom signal should ingest");
    }

    assert_eq!(api.tracked_sources(), CorrelationApi::MAX_TRACKED_SOURCES);
    assert_eq!(
        api.total_events_processed(),
        CorrelationApi::MAX_TRACKED_SOURCES as u64 + 1
    );

    let expected_source = source_ip(CorrelationApi::MAX_TRACKED_SOURCES).to_string();
    let mut source_out = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
    let source_len = api.write_last_source_ip(&mut source_out);
    let source_text = std::str::from_utf8(&source_out[..source_len])
        .expect("source IP should remain valid UTF-8");
    assert_eq!(source_text, expected_source);
}

#[test]
fn fail_closed_public_errors_do_not_create_last_result() {
    let api = production_api();
    let source_ip = source_ip(7);

    assert!(!api.has_last_result());
    assert_eq!(api.total_events_processed(), 0);

    let ingest = api.observe_artifact_access(source_ip, "", "artifact", "tag", 100.0);
    assert!(ingest.is_err());
    assert!(!api.has_last_result());
    assert_eq!(api.total_events_processed(), 0);

    assert!(api.record_response_for_source(source_ip).is_err());
    assert!(api.prune_stale_sources(0).is_err());
}
