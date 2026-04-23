//! Hardened policy conversion and response evaluation for correlation runtime.

use crate::events::{EventContext, EventKind, MAX_LABEL_LEN};
use crate::failures::{
    MAX_INTERNAL_ERROR_LEN, config_conversion_error, rule_evaluation_error,
    severity_rule_error_message,
};
use crate::matching::{contains_ascii_case_insensitive, hash_ascii_case_insensitive};
use crate::runtime::{
    ACTION_ALERT, ACTION_CUSTOM_SCRIPT, ACTION_ISOLATE_HOST, ACTION_KILL_PROCESS, ACTION_LOG,
    ActionDescriptor, MAX_ACTION_PATH_LEN, MAX_HISTORY_DEPTH, MAX_RESPONSE_CONDITIONS,
    MAX_SUSPICIOUS_PATTERNS, MAX_SUSPICIOUS_PROCESSES, SEVERITY_CRITICAL, SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL, SEVERITY_LOW, SEVERITY_MEDIUM, SourceState,
};
use heapless::{String as HString, Vec as HVec};
use palisade_config::{ActionType, PolicyConfig, ResponseCondition, ResponseRule, Severity};
use palisade_errors::AgentError;
use std::fmt::Write as _;

pub(crate) struct RuntimeCorrelationPolicy {
    pub(crate) correlation_window_secs: u64,
    pub(crate) alert_threshold: f64,
    pub(crate) max_events_per_source: usize,
    pub(crate) enable_time_scoring: bool,
    pub(crate) enable_ancestry_tracking: bool,
    business_hours_start: u8,
    business_hours_end: u8,
    weights: RuntimeWeights,
    cooldown_secs: u64,
    max_kills_per_incident: usize,
    dry_run: bool,
    suspicious_processes: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PROCESSES>,
    suspicious_patterns: HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>,
    response_rules: [Option<RuntimeResponseRule>; 4],
}

impl RuntimeCorrelationPolicy {
    pub(crate) fn from_policy(policy: &PolicyConfig) -> Result<Self, AgentError> {
        policy.validate()?;

        if policy.scoring.max_events_in_memory > MAX_HISTORY_DEPTH {
            let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
            let _ = write!(
                &mut message,
                "operation=convert_policy; scoring.max_events_in_memory={} exceeds hardened fixed-capacity limit ({MAX_HISTORY_DEPTH})",
                policy.scoring.max_events_in_memory
            );
            return Err(config_conversion_error(
                message.as_str(),
                "scoring.max_events_in_memory",
            ));
        }

        validate_hour_range(
            "scoring.business_hours_start",
            policy.scoring.business_hours_start,
        )?;
        validate_hour_range(
            "scoring.business_hours_end",
            policy.scoring.business_hours_end,
        )?;
        if policy.scoring.business_hours_start == policy.scoring.business_hours_end {
            return Err(config_conversion_error(
                "operation=convert_policy; business-hours window cannot be zero-length",
                "scoring.business_hours_start",
            ));
        }

        validate_weight(
            "scoring.weights.artifact_access",
            policy.scoring.weights.artifact_access,
        )?;
        validate_weight(
            "scoring.weights.suspicious_process",
            policy.scoring.weights.suspicious_process,
        )?;
        validate_weight(
            "scoring.weights.rapid_enumeration",
            policy.scoring.weights.rapid_enumeration,
        )?;
        validate_weight(
            "scoring.weights.off_hours_activity",
            policy.scoring.weights.off_hours_activity,
        )?;
        validate_weight(
            "scoring.weights.ancestry_suspicious",
            policy.scoring.weights.ancestry_suspicious,
        )?;

        let mut suspicious_processes =
            HVec::<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PROCESSES>::new();
        for process_name in &policy.deception.suspicious_processes {
            push_hstring(
                "deception.suspicious_processes",
                process_name,
                &mut suspicious_processes,
            )?;
        }

        let mut suspicious_patterns =
            HVec::<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>::new();
        for pattern in &policy.deception.suspicious_patterns {
            push_hstring(
                "deception.suspicious_patterns",
                pattern,
                &mut suspicious_patterns,
            )?;
        }

        let mut response_rules = core::array::from_fn(|_| None);
        for rule in &policy.response.rules {
            response_rules[severity_rule_index(&rule.severity)] = Some(
                RuntimeResponseRule::from_rule(rule, policy.scoring.enable_ancestry_tracking)?,
            );
        }

        Ok(Self {
            correlation_window_secs: policy.scoring.correlation_window_secs,
            alert_threshold: policy.scoring.alert_threshold,
            max_events_per_source: policy.scoring.max_events_in_memory,
            enable_time_scoring: policy.scoring.enable_time_scoring,
            enable_ancestry_tracking: policy.scoring.enable_ancestry_tracking,
            business_hours_start: policy.scoring.business_hours_start,
            business_hours_end: policy.scoring.business_hours_end,
            weights: RuntimeWeights {
                artifact_access: policy.scoring.weights.artifact_access,
                suspicious_process: policy.scoring.weights.suspicious_process,
                rapid_enumeration: policy.scoring.weights.rapid_enumeration,
                off_hours_activity: policy.scoring.weights.off_hours_activity,
                ancestry_suspicious: policy.scoring.weights.ancestry_suspicious,
            },
            cooldown_secs: policy.response.cooldown_secs,
            max_kills_per_incident: policy.response.max_kills_per_incident,
            dry_run: policy.response.dry_run,
            suspicious_processes,
            suspicious_patterns,
            response_rules,
        })
    }

    pub(crate) fn is_suspicious_process(&self, process_name: &str) -> bool {
        self.suspicious_processes
            .iter()
            .any(|pattern| contains_ascii_case_insensitive(process_name, pattern.as_str()))
    }

    pub(crate) fn cooldown_secs(&self) -> u64 {
        self.cooldown_secs
    }
}

struct RuntimeWeights {
    artifact_access: f64,
    suspicious_process: f64,
    rapid_enumeration: f64,
    off_hours_activity: f64,
    ancestry_suspicious: f64,
}

struct RuntimeResponseRule {
    action: RuntimeAction,
    conditions: HVec<RuntimeResponseCondition, MAX_RESPONSE_CONDITIONS>,
}

impl RuntimeResponseRule {
    fn from_rule(rule: &ResponseRule, enable_ancestry_tracking: bool) -> Result<Self, AgentError> {
        let mut conditions = HVec::<RuntimeResponseCondition, MAX_RESPONSE_CONDITIONS>::new();
        for condition in &rule.conditions {
            conditions
                .push(RuntimeResponseCondition::from_condition(
                    condition,
                    enable_ancestry_tracking,
                )?)
                .map_err(|_| {
                    config_conversion_error(
                        "operation=convert_policy; response rule exceeds fixed-capacity condition limit",
                        "response.rules.conditions",
                    )
                })?;
        }

        Ok(Self {
            action: RuntimeAction::from_action(&rule.action)?,
            conditions,
        })
    }
}

enum RuntimeAction {
    Log,
    Alert,
    KillProcess,
    IsolateHost,
    CustomScript(HString<MAX_ACTION_PATH_LEN>),
}

impl RuntimeAction {
    fn from_action(action: &ActionType) -> Result<Self, AgentError> {
        match action {
            ActionType::Log => Ok(Self::Log),
            ActionType::Alert => Ok(Self::Alert),
            ActionType::KillProcess => Ok(Self::KillProcess),
            ActionType::IsolateHost => Ok(Self::IsolateHost),
            ActionType::CustomScript { path } => {
                if !path.is_absolute() {
                    return Err(config_conversion_error(
                        "operation=convert_policy; custom script path must be absolute",
                        "response.rules.action.path",
                    ));
                }

                let path_text = path.to_str().ok_or_else(|| {
                    config_conversion_error(
                        "operation=convert_policy; custom script path must be valid UTF-8 for no-allocation mode",
                        "response.rules.action.path",
                    )
                })?;

                let mut fixed = HString::<MAX_ACTION_PATH_LEN>::new();
                fixed.push_str(path_text).map_err(|_| {
                    config_conversion_error(
                        "operation=convert_policy; custom script path exceeds fixed-capacity limit",
                        "response.rules.action.path",
                    )
                })?;
                Ok(Self::CustomScript(fixed))
            }
        }
    }

    fn to_descriptor(&self) -> ActionDescriptor {
        let mut descriptor = ActionDescriptor::new();
        match self {
            Self::Log => {
                descriptor.code = ACTION_LOG;
            }
            Self::Alert => {
                descriptor.code = ACTION_ALERT;
            }
            Self::KillProcess => {
                descriptor.code = ACTION_KILL_PROCESS;
            }
            Self::IsolateHost => {
                descriptor.code = ACTION_ISOLATE_HOST;
            }
            Self::CustomScript(path) => {
                descriptor.code = ACTION_CUSTOM_SCRIPT;
                descriptor.set_script_path(path.as_str());
            }
        }
        descriptor
    }
}

enum RuntimeResponseCondition {
    MinConfidence { threshold: f64 },
    NotParentedBy { process_name_hash: u64 },
    MinSignalTypes { count: usize },
    RepeatCount { count: usize, window_secs: u64 },
    TimeWindow { start_hour: u8, end_hour: u8 },
}

impl RuntimeResponseCondition {
    fn from_condition(
        condition: &ResponseCondition,
        enable_ancestry_tracking: bool,
    ) -> Result<Self, AgentError> {
        match condition {
            ResponseCondition::MinConfidence { threshold } => {
                if !threshold.is_finite() || !(0.0..=100.0).contains(threshold) {
                    return Err(config_conversion_error(
                        "operation=convert_policy; min_confidence threshold must be finite and within [0, 100]",
                        "response.rules.conditions.threshold",
                    ));
                }

                Ok(Self::MinConfidence {
                    threshold: *threshold,
                })
            }
            ResponseCondition::NotParentedBy { process_name } => {
                if !enable_ancestry_tracking {
                    return Err(config_conversion_error(
                        "operation=convert_policy; not_parented_by requires scoring.enable_ancestry_tracking=true",
                        "response.rules.conditions",
                    ));
                }

                Ok(Self::NotParentedBy {
                    process_name_hash: hash_ascii_case_insensitive(process_name),
                })
            }
            ResponseCondition::MinSignalTypes { count } => {
                if *count == 0 {
                    return Err(config_conversion_error(
                        "operation=convert_policy; min_signal_types count must be non-zero",
                        "response.rules.conditions.count",
                    ));
                }

                Ok(Self::MinSignalTypes { count: *count })
            }
            ResponseCondition::RepeatCount { count, window_secs } => {
                if *count == 0 || *window_secs == 0 {
                    return Err(config_conversion_error(
                        "operation=convert_policy; repeat_count requires non-zero count and window",
                        "response.rules.conditions",
                    ));
                }

                Ok(Self::RepeatCount {
                    count: *count,
                    window_secs: *window_secs,
                })
            }
            ResponseCondition::TimeWindow {
                start_hour,
                end_hour,
            } => {
                validate_hour_range("response.rules.conditions.start_hour", *start_hour)?;
                validate_hour_range("response.rules.conditions.end_hour", *end_hour)?;
                if start_hour == end_hour {
                    return Err(config_conversion_error(
                        "operation=convert_policy; time_window cannot be zero-length",
                        "response.rules.conditions",
                    ));
                }

                Ok(Self::TimeWindow {
                    start_hour: *start_hour,
                    end_hour: *end_hour,
                })
            }
            ResponseCondition::Custom { .. } => Err(config_conversion_error(
                "operation=convert_policy; custom response conditions are not supported by the hardened correlation runtime",
                "response.rules.conditions",
            )),
        }
    }
}

pub(crate) fn calculate_base_score(
    event: &EventContext<'_>,
    policy: &RuntimeCorrelationPolicy,
) -> f64 {
    let mut base = match event.kind {
        EventKind::ArtifactAccess { .. } => policy.weights.artifact_access,
        EventKind::SuspiciousProcess { .. } => policy.weights.suspicious_process,
        EventKind::RapidEnumeration { .. } => policy.weights.rapid_enumeration,
        EventKind::OffHoursActivity { hour } => {
            if policy.enable_time_scoring
                && !hour_in_window(hour, policy.business_hours_start, policy.business_hours_end)
            {
                policy.weights.off_hours_activity
            } else {
                0.0
            }
        }
        EventKind::SuspiciousAncestry { .. } => {
            if policy.enable_ancestry_tracking {
                policy.weights.ancestry_suspicious
            } else {
                0.0
            }
        }
        EventKind::AuthenticationFailure { .. } => 15.0,
        EventKind::PathTraversal { .. } => 25.0,
        EventKind::SqlInjection { .. } => 30.0,
        EventKind::CommandInjection { .. } => 35.0,
        EventKind::ConfigurationChange { .. } => 10.0,
        EventKind::ErrorEvent { .. } => 5.0,
        EventKind::NetworkProbe { .. } => 18.0,
        EventKind::MalwareDownload { .. } => 40.0,
        EventKind::C2Communication { .. } => 45.0,
        EventKind::Custom { .. } => 10.0,
    };

    if event_matches_suspicious_pattern(&event.kind, &policy.suspicious_patterns) {
        base += 10.0;
    }

    base * (event.confidence / 100.0)
}

pub(crate) fn determine_action(
    policy: &RuntimeCorrelationPolicy,
    event: &EventContext<'_>,
    final_score: f64,
    severity_code: u8,
    source_state: &SourceState,
    on_cooldown: bool,
) -> Result<ActionDescriptor, AgentError> {
    if final_score < policy.alert_threshold {
        return Ok(RuntimeAction::Log.to_descriptor());
    }

    let severity_index = severity_to_rule_index(severity_code)?;
    let Some(rule) = &policy.response_rules[severity_index] else {
        return Ok(RuntimeAction::Log.to_descriptor());
    };

    for condition in &rule.conditions {
        let satisfied = match condition {
            RuntimeResponseCondition::MinConfidence { threshold } => event.confidence >= *threshold,
            RuntimeResponseCondition::NotParentedBy { process_name_hash } => {
                match source_state.recent_ancestry_contains(
                    *process_name_hash,
                    event.timestamp_secs,
                    policy.correlation_window_secs,
                ) {
                    Some(is_parented_by_blocker) => !is_parented_by_blocker,
                    None => false,
                }
            }
            RuntimeResponseCondition::MinSignalTypes { count } => {
                source_state.distinct_signal_types_within(
                    event.timestamp_secs,
                    policy.correlation_window_secs,
                ) >= *count
            }
            RuntimeResponseCondition::RepeatCount { count, window_secs } => {
                source_state.event_count_within(event.timestamp_secs, *window_secs) >= *count
            }
            RuntimeResponseCondition::TimeWindow {
                start_hour,
                end_hour,
            } => hour_in_window(event.current_hour, *start_hour, *end_hour),
        };

        if !satisfied {
            return Ok(RuntimeAction::Log.to_descriptor());
        }
    }

    if on_cooldown {
        return Ok(RuntimeAction::Log.to_descriptor());
    }

    let descriptor = rule.action.to_descriptor();
    if !descriptor.is_destructive() {
        return Ok(descriptor);
    }

    if policy.dry_run {
        return Ok(RuntimeAction::Log.to_descriptor());
    }

    if source_state.destructive_actions_in_window >= policy.max_kills_per_incident {
        return Ok(RuntimeAction::Alert.to_descriptor());
    }

    Ok(descriptor)
}

pub(crate) fn severity_from_score(score: f64) -> u8 {
    if !score.is_finite() {
        SEVERITY_INFORMATIONAL
    } else if score < 40.0 {
        SEVERITY_LOW
    } else if score < 60.0 {
        SEVERITY_MEDIUM
    } else if score < 80.0 {
        SEVERITY_HIGH
    } else {
        SEVERITY_CRITICAL
    }
}

fn severity_rule_index(severity: &Severity) -> usize {
    match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

fn severity_to_rule_index(severity_code: u8) -> Result<usize, AgentError> {
    match severity_code {
        SEVERITY_LOW => Ok(0),
        SEVERITY_MEDIUM => Ok(1),
        SEVERITY_HIGH => Ok(2),
        SEVERITY_CRITICAL => Ok(3),
        _ => Err(rule_evaluation_error(
            severity_rule_error_message(severity_code).as_str(),
            "severity",
        )),
    }
}

fn push_hstring<const N: usize, const M: usize>(
    field: &str,
    value: &str,
    out: &mut HVec<HString<N>, M>,
) -> Result<(), AgentError> {
    let mut item = HString::<N>::new();
    item.push_str(value).map_err(|_| {
        let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut message,
            "operation=convert_policy; field={field}; value exceeds fixed-capacity limit ({N} bytes)"
        );
        config_conversion_error(message.as_str(), field)
    })?;

    out.push(item).map_err(|_| {
        let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut message,
            "operation=convert_policy; field={field}; too many entries for fixed-capacity limit ({M})"
        );
        config_conversion_error(message.as_str(), field)
    })?;

    Ok(())
}

fn validate_weight(field: &str, value: f64) -> Result<(), AgentError> {
    if !value.is_finite() || value < 0.0 {
        let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut message,
            "operation=convert_policy; field={field}; weight must be finite and non-negative"
        );
        return Err(config_conversion_error(message.as_str(), field));
    }

    Ok(())
}

fn validate_hour_range(field: &str, hour: u8) -> Result<(), AgentError> {
    if hour > 23 {
        let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut message,
            "operation=convert_policy; field={field}; hour must be within 0-23"
        );
        return Err(config_conversion_error(message.as_str(), field));
    }

    Ok(())
}

fn event_matches_suspicious_pattern(
    kind: &EventKind<'_>,
    patterns: &HVec<HString<MAX_LABEL_LEN>, MAX_SUSPICIOUS_PATTERNS>,
) -> bool {
    patterns
        .iter()
        .any(|pattern| event_contains_pattern(kind, pattern.as_str()))
}

fn event_contains_pattern(kind: &EventKind<'_>, pattern: &str) -> bool {
    match kind {
        EventKind::ArtifactAccess {
            artifact_id,
            artifact_tag,
        } => {
            contains_ascii_case_insensitive(artifact_id, pattern)
                || contains_ascii_case_insensitive(artifact_tag, pattern)
        }
        EventKind::SuspiciousProcess { process_name, .. } => {
            contains_ascii_case_insensitive(process_name, pattern)
        }
        EventKind::SuspiciousAncestry { process_chain } => process_chain
            .iter()
            .any(|process_name| contains_ascii_case_insensitive(process_name, pattern)),
        EventKind::AuthenticationFailure { username, method } => {
            contains_ascii_case_insensitive(username, pattern)
                || contains_ascii_case_insensitive(method, pattern)
        }
        EventKind::PathTraversal { attempted_path } => {
            contains_ascii_case_insensitive(attempted_path, pattern)
        }
        EventKind::SqlInjection { payload } => contains_ascii_case_insensitive(payload, pattern),
        EventKind::CommandInjection { command } => {
            contains_ascii_case_insensitive(command, pattern)
        }
        EventKind::ConfigurationChange {
            field,
            old_value,
            new_value,
        } => {
            contains_ascii_case_insensitive(field, pattern)
                || contains_ascii_case_insensitive(old_value, pattern)
                || contains_ascii_case_insensitive(new_value, pattern)
        }
        EventKind::ErrorEvent {
            error_code,
            operation,
            category,
        } => {
            contains_ascii_case_insensitive(error_code, pattern)
                || contains_ascii_case_insensitive(operation, pattern)
                || contains_ascii_case_insensitive(category, pattern)
        }
        EventKind::NetworkProbe { ports, protocol } => {
            contains_ascii_case_insensitive(ports, pattern)
                || contains_ascii_case_insensitive(protocol, pattern)
        }
        EventKind::MalwareDownload { source, hash } => {
            contains_ascii_case_insensitive(source, pattern)
                || hash
                    .map(|value| contains_ascii_case_insensitive(value, pattern))
                    .unwrap_or(false)
        }
        EventKind::C2Communication {
            destination,
            protocol,
        } => {
            contains_ascii_case_insensitive(destination, pattern)
                || contains_ascii_case_insensitive(protocol, pattern)
        }
        EventKind::Custom { type_id } => contains_ascii_case_insensitive(type_id, pattern),
        EventKind::RapidEnumeration { .. } | EventKind::OffHoursActivity { .. } => false,
    }
}

fn hour_in_window(hour: u8, start_hour: u8, end_hour: u8) -> bool {
    if start_hour < end_hour {
        hour >= start_hour && hour < end_hour
    } else {
        hour >= start_hour || hour < end_hour
    }
}
