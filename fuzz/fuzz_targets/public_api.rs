#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_config::{ActionType, PolicyConfig, ResponseCondition, ResponseRule, Severity};
use palisade_correlation::CorrelationApi;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

const MAX_FIELD_LEN: usize = 32;

fuzz_target!(|data: &[u8]| {
    let mut stream = ByteStream::new(data);
    let policy = build_supported_policy(&mut stream);
    let Ok(api) = CorrelationApi::new(&policy) else {
        return;
    };
    let api = api.with_timing_floor(Duration::from_micros(u64::from(stream.next_u8() % 8)));

    let mut pattern_codes = [0u16; CorrelationApi::MAX_PATTERN_CODES];
    let mut source_ip_buf = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
    let mut script_path_buf = [0u8; CorrelationApi::MAX_ACTION_SCRIPT_PATH_LEN];

    let steps = 1 + stream.bounded_usize(32);
    for _ in 0..steps {
        let source_ip = next_ip(&mut stream);
        let confidence = f64::from(stream.next_u8());

        match stream.next_u8() % 18 {
            0 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let artifact_id = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let artifact_tag = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_artifact_access(
                    source_ip,
                    session.as_str(),
                    artifact_id.as_str(),
                    artifact_tag.as_str(),
                    confidence,
                );
            }
            1 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let process_name = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let pid = u32::from(stream.next_u16());
                let _ = api.observe_suspicious_process(
                    source_ip,
                    session.as_str(),
                    process_name.as_str(),
                    pid,
                    confidence,
                );
                let _ = api.is_suspicious_process(process_name.as_str());
            }
            2 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let target_count = stream.bounded_usize(256);
                let time_window_secs = u64::from(stream.next_u16());
                let _ = api.observe_rapid_enumeration(
                    source_ip,
                    session.as_str(),
                    target_count,
                    time_window_secs,
                    confidence,
                );
            }
            3 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let hour = stream.next_u8();
                let _ = api.observe_off_hours_activity(source_ip, session.as_str(), hour, confidence);
            }
            4 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let chain0 = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let chain1 = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let chain2 = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let chain_len = 1 + stream.bounded_usize(3);
                let chain = [chain0.as_str(), chain1.as_str(), chain2.as_str()];
                let _ = api.observe_suspicious_ancestry(
                    source_ip,
                    session.as_str(),
                    &chain[..chain_len],
                    confidence,
                );
            }
            5 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let username = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let method = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_authentication_failure(
                    source_ip,
                    session.as_str(),
                    username.as_str(),
                    method.as_str(),
                    confidence,
                );
            }
            6 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let attempted_path = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_path_traversal(
                    source_ip,
                    session.as_str(),
                    attempted_path.as_str(),
                    confidence,
                );
            }
            7 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let payload = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ =
                    api.observe_sql_injection(source_ip, session.as_str(), payload.as_str(), confidence);
            }
            8 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let command = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_command_injection(
                    source_ip,
                    session.as_str(),
                    command.as_str(),
                    confidence,
                );
            }
            9 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let field = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let old_value = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let new_value = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_configuration_change(
                    source_ip,
                    session.as_str(),
                    field.as_str(),
                    old_value.as_str(),
                    new_value.as_str(),
                    confidence,
                );
            }
            10 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let error_code = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let operation = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let category = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_error(
                    source_ip,
                    session.as_str(),
                    error_code.as_str(),
                    operation.as_str(),
                    category.as_str(),
                    confidence,
                );
            }
            11 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let ports = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let protocol = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_network_probe(
                    source_ip,
                    session.as_str(),
                    ports.as_str(),
                    protocol.as_str(),
                    confidence,
                );
            }
            12 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let source = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let hash = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let maybe_hash = stream.next_bool().then_some(hash.as_str());
                let _ = api.observe_malware_download(
                    source_ip,
                    session.as_str(),
                    source.as_str(),
                    maybe_hash,
                    confidence,
                );
            }
            13 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let destination = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let protocol = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ = api.observe_c2_communication(
                    source_ip,
                    session.as_str(),
                    destination.as_str(),
                    protocol.as_str(),
                    confidence,
                );
            }
            14 => {
                let session = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let type_id = FieldBuf::<MAX_FIELD_LEN>::from_stream(&mut stream, true);
                let _ =
                    api.observe_custom_signal(source_ip, session.as_str(), type_id.as_str(), confidence);
            }
            15 => {
                let _ = api.record_response_for_source(source_ip);
            }
            16 => {
                let max_age_secs = u64::from(stream.next_u16());
                let _ = api.prune_stale_sources(max_age_secs);
            }
            _ => {
                let reload_policy = build_reload_policy(&mut stream);
                let _ = api.reload_policy(&reload_policy);
            }
        }

        let _ = api.has_last_result();
        let _ = api.last_score();
        let _ = api.last_severity_code();
        let _ = api.last_action_code();
        let _ = api.last_on_cooldown();
        let _ = api.last_kill_chain_stage_code();
        let _ = api.last_pattern_count();
        let _ = api.write_last_pattern_codes(&mut pattern_codes);
        let _ = api.write_last_source_ip(&mut source_ip_buf);
        let _ = api.write_last_action_script_path(&mut script_path_buf);
        let _ = api.total_events_processed();
        let _ = api.tracked_sources();
    }
});

fn build_supported_policy(stream: &mut ByteStream<'_>) -> PolicyConfig {
    let mut policy = PolicyConfig::default();
    policy.scoring.max_events_in_memory = 1 + stream.bounded_usize(CorrelationApi::MAX_EVENTS_PER_SOURCE);
    policy.scoring.correlation_window_secs = 1 + u64::from(stream.next_u16() % 3600);
    policy.scoring.alert_threshold = f64::from(stream.next_u8());
    policy.scoring.enable_time_scoring = stream.next_bool();
    policy.scoring.enable_ancestry_tracking = stream.next_bool();
    policy.scoring.weights.artifact_access = f64::from(stream.next_u8());
    policy.scoring.weights.suspicious_process = f64::from(stream.next_u8());
    policy.scoring.weights.rapid_enumeration = f64::from(stream.next_u8());
    policy.scoring.weights.off_hours_activity = f64::from(stream.next_u8());
    policy.scoring.weights.ancestry_suspicious = f64::from(stream.next_u8());

    let start_hour = stream.next_u8() % 24;
    let mut end_hour = stream.next_u8() % 24;
    if start_hour == end_hour {
        end_hour = (end_hour + 1) % 24;
    }
    policy.scoring.business_hours_start = start_hour;
    policy.scoring.business_hours_end = end_hour;

    policy.response.cooldown_secs = 1 + u64::from(stream.next_u16() % 3600);
    policy.response.max_kills_per_incident = 1 + stream.bounded_usize(16);
    policy.response.dry_run = stream.next_bool();
    policy.response.rules = vec![
        build_rule(stream, Severity::Low, policy.scoring.enable_ancestry_tracking),
        build_rule(stream, Severity::Medium, policy.scoring.enable_ancestry_tracking),
        build_rule(stream, Severity::High, policy.scoring.enable_ancestry_tracking),
        build_rule(stream, Severity::Critical, policy.scoring.enable_ancestry_tracking),
    ];

    if stream.next_bool() {
        policy.deception.suspicious_patterns = vec!["token".to_string(), "admin".to_string()].into_boxed_slice();
    }

    policy
}

fn build_reload_policy(stream: &mut ByteStream<'_>) -> PolicyConfig {
    let mut policy = build_supported_policy(stream);

    if stream.next_bool() {
        policy.scoring.max_events_in_memory = CorrelationApi::MAX_EVENTS_PER_SOURCE + 1;
    }

    if stream.next_bool() {
        policy.response.rules[0].conditions = vec![ResponseCondition::Custom {
            name: "geo_allowlist".to_string(),
            params: HashMap::new(),
        }];

        if stream.next_bool() {
            policy.registered_custom_conditions = HashSet::from(["geo_allowlist".to_string()]);
        }
    }

    policy
}

fn build_rule(
    stream: &mut ByteStream<'_>,
    severity: Severity,
    enable_ancestry_tracking: bool,
) -> ResponseRule {
    let min_confidence = ResponseCondition::MinConfidence {
        threshold: f64::from(stream.next_u8()),
    };
    let min_signal_types = ResponseCondition::MinSignalTypes {
        count: 1 + stream.bounded_usize(4),
    };
    let repeat_count = ResponseCondition::RepeatCount {
        count: 1 + stream.bounded_usize(8),
        window_secs: 1 + u64::from(stream.next_u16() % 600),
    };
    let start_hour = stream.next_u8() % 24;
    let mut end_hour = stream.next_u8() % 24;
    if start_hour == end_hour {
        end_hour = (end_hour + 1) % 24;
    }
    let time_window = ResponseCondition::TimeWindow {
        start_hour,
        end_hour,
    };

    let mut conditions = Vec::new();
    if stream.next_bool() {
        conditions.push(min_confidence);
    }
    if stream.next_bool() {
        conditions.push(min_signal_types);
    }
    if stream.next_bool() {
        conditions.push(repeat_count);
    }
    if stream.next_bool() {
        conditions.push(time_window);
    }
    if enable_ancestry_tracking && stream.next_bool() {
        conditions.push(ResponseCondition::NotParentedBy {
            process_name: "palisade-agent".to_string(),
        });
    }

    ResponseRule {
        severity,
        conditions,
        action: build_action(stream),
    }
}

fn build_action(stream: &mut ByteStream<'_>) -> ActionType {
    match stream.next_u8() % 5 {
        0 => ActionType::Log,
        1 => ActionType::Alert,
        2 => ActionType::KillProcess,
        3 => ActionType::IsolateHost,
        _ => ActionType::CustomScript {
            path: PathBuf::from("/bin/true"),
        },
    }
}

fn next_ip(stream: &mut ByteStream<'_>) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        stream.next_u8(),
        stream.next_u8(),
        stream.next_u8(),
        stream.next_u8(),
    ))
}

struct ByteStream<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> ByteStream<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let byte = self.bytes.get(self.index).copied().unwrap_or(0);
        self.index = self.index.saturating_add(1);
        byte
    }

    fn next_u16(&mut self) -> u16 {
        u16::from(self.next_u8()) << 8 | u16::from(self.next_u8())
    }

    fn next_bool(&mut self) -> bool {
        self.next_u8() & 1 == 1
    }

    fn bounded_usize(&mut self, upper_bound: usize) -> usize {
        if upper_bound == 0 {
            0
        } else {
            usize::from(self.next_u16()) % upper_bound
        }
    }
}

struct FieldBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FieldBuf<N> {
    fn from_stream(stream: &mut ByteStream<'_>, allow_empty: bool) -> Self {
        let mut field = Self {
            bytes: [0; N],
            len: 0,
        };
        let span = if allow_empty { N + 1 } else { N };
        let base_len = stream.bounded_usize(span);
        field.len = if allow_empty { base_len } else { base_len + 1 };

        for slot in &mut field.bytes[..field.len] {
            *slot = sanitize_ascii(stream.next_u8());
        }

        field
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

fn sanitize_ascii(byte: u8) -> u8 {
    match byte % 40 {
        value @ 0..=25 => b'a' + value,
        value @ 26..=35 => b'0' + (value - 26),
        36 => b'-',
        37 => b'_',
        38 => b'.',
        _ => b'/',
    }
}
