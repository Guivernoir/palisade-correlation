//! Fixed-capacity internal engine for the public correlation API.

use crate::events::EventContext;
use crate::failures::{context_error, invalid_score_error};
use crate::matching::copy_str_to_buffer;
use crate::patterns::{
    MAX_PATTERNS_PER_RESULT, detect_patterns, infer_kill_chain_stage, push_unique_campaign_pattern,
};
use crate::policy::{
    RuntimeCorrelationPolicy, calculate_base_score, determine_action, severity_from_score,
};
use crate::runtime::{CorrelationState, SourceState};
use crate::timing::now_secs;
use heapless::Vec as HVec;
use palisade_config::PolicyConfig;
use palisade_errors::AgentError;
use std::fmt::Write as _;
use std::net::IpAddr;

pub(crate) use crate::runtime::{
    ACTION_ALERT, ACTION_CUSTOM_SCRIPT, ACTION_ISOLATE_HOST, ACTION_KILL_PROCESS, ACTION_LOG,
    MAX_ACTION_PATH_LEN, MAX_HISTORY_DEPTH, MAX_IP_TEXT_LEN, MAX_TRACKED_SOURCES,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFORMATIONAL, SEVERITY_LOW, SEVERITY_MEDIUM,
};

pub(crate) struct CorrelationEngine {
    policy: RuntimeCorrelationPolicy,
    state: CorrelationState,
}

impl CorrelationEngine {
    pub(crate) fn from_policy(policy: &PolicyConfig) -> Result<Self, AgentError> {
        Ok(Self {
            policy: RuntimeCorrelationPolicy::from_policy(policy)?,
            state: CorrelationState::new(),
        })
    }

    pub(crate) fn reload_policy(&mut self, policy: &PolicyConfig) -> Result<(), AgentError> {
        self.policy = RuntimeCorrelationPolicy::from_policy(policy)?;
        Ok(())
    }

    pub(crate) fn is_suspicious_process(&self, process_name: &str) -> bool {
        self.policy.is_suspicious_process(process_name)
    }

    pub(crate) fn process(&mut self, event: EventContext<'_>) -> Result<(), AgentError> {
        self.state.total_events_processed = self.state.total_events_processed.saturating_add(1);

        let base_score = calculate_base_score(&event, &self.policy);
        if !base_score.is_finite() || base_score < 0.0 {
            return Err(invalid_score_error(
                "operation=calculate_base_score; derived score is not finite",
                "score",
            ));
        }

        self.ensure_source_slot(event.source_ip, event.timestamp_secs)?;

        let source_state = self
            .state
            .sources
            .get_mut(&event.source_ip)
            .ok_or_else(|| {
                context_error(
                    "operation=process_event; source state missing after slot reservation",
                    "source_ip",
                )
            })?;

        source_state.record_observed(
            event.kind.observed_kind_code(),
            event.timestamp_secs,
            self.policy.max_events_per_source,
            self.policy.correlation_window_secs,
        )?;

        if self.policy.enable_ancestry_tracking {
            source_state.update_ancestry_context(&event)?;
        }

        source_state.last_activity = event.timestamp_secs;

        let mut detected_patterns = HVec::<u16, MAX_PATTERNS_PER_RESULT>::new();
        detect_patterns(&event, &source_state.history, &mut detected_patterns);

        for pattern in &detected_patterns {
            push_unique_campaign_pattern(&mut source_state.patterns, *pattern);
        }

        source_state.kill_chain_stage_code =
            infer_kill_chain_stage(source_state.patterns.as_slice());

        let boost = ((source_state.history.len().saturating_sub(1)) as f64 * 2.0).min(20.0);
        let final_score = base_score + boost;
        if !final_score.is_finite() || final_score < 0.0 {
            return Err(invalid_score_error(
                "operation=process_event; final score is not finite",
                "score",
            ));
        }

        let severity_code = severity_from_score(final_score);
        let on_cooldown = source_state.last_response_secs != 0
            && event
                .timestamp_secs
                .saturating_sub(source_state.last_response_secs)
                < self.policy.cooldown_secs();

        let resolved_action = determine_action(
            &self.policy,
            &event,
            final_score,
            severity_code,
            source_state,
            on_cooldown,
        )?;

        if resolved_action.is_destructive() {
            source_state.destructive_actions_in_window =
                source_state.destructive_actions_in_window.saturating_add(1);
        }

        self.state.last_outcome.record(
            event.source_ip,
            final_score,
            severity_code,
            resolved_action,
            on_cooldown,
            source_state.kill_chain_stage_code,
            &detected_patterns,
        );

        Ok(())
    }

    pub(crate) fn record_response_for_source(
        &mut self,
        source_ip: IpAddr,
    ) -> Result<(), AgentError> {
        let now = now_secs()?;
        let source_state = self.state.sources.get_mut(&source_ip).ok_or_else(|| {
            context_error(
                "operation=record_response_for_source; source_ip is not currently tracked",
                "source_ip",
            )
        })?;
        source_state.last_response_secs = now;
        Ok(())
    }

    pub(crate) fn prune_stale_sources(&mut self, max_age_secs: u64) -> Result<(), AgentError> {
        if max_age_secs == 0 {
            return Err(context_error(
                "operation=prune_stale_sources; max_age_secs must be non-zero",
                "max_age_secs",
            ));
        }

        let now = now_secs()?;
        let mut stale_sources = heapless::Vec::<IpAddr, MAX_TRACKED_SOURCES>::new();

        for (source_ip, source_state) in &self.state.sources {
            if now.saturating_sub(source_state.last_activity) >= max_age_secs {
                stale_sources.push(*source_ip).map_err(|_| {
                    crate::failures::buffer_error(
                        "operation=prune_stale_sources; stale-source buffer exhausted",
                        "sources",
                    )
                })?;
            }
        }

        for source_ip in stale_sources {
            let _ = self.state.sources.remove(&source_ip);
        }

        Ok(())
    }

    pub(crate) fn has_last_result(&self) -> bool {
        self.state.last_outcome.has_result
    }

    pub(crate) fn last_score(&self) -> f64 {
        self.state.last_outcome.score
    }

    pub(crate) fn last_severity_code(&self) -> u8 {
        self.state.last_outcome.severity_code
    }

    pub(crate) fn last_action_code(&self) -> u8 {
        self.state.last_outcome.action.code
    }

    pub(crate) fn last_on_cooldown(&self) -> bool {
        self.state.last_outcome.on_cooldown
    }

    pub(crate) fn last_kill_chain_stage_code(&self) -> u8 {
        self.state.last_outcome.kill_chain_stage_code
    }

    pub(crate) fn last_pattern_codes(&self) -> &[u16] {
        self.state.last_outcome.pattern_codes.as_slice()
    }

    pub(crate) fn write_last_action_script_path(&self, out: &mut [u8]) -> usize {
        self.state.last_outcome.action.write_script_path(out)
    }

    pub(crate) fn write_last_source_ip(&self, out: &mut [u8]) -> usize {
        let Some(source_ip) = self.state.last_outcome.source_ip else {
            return 0;
        };

        let mut ip_text = heapless::String::<MAX_IP_TEXT_LEN>::new();
        let _ = write!(&mut ip_text, "{source_ip}");
        copy_str_to_buffer(ip_text.as_str(), out)
    }

    pub(crate) fn total_events_processed(&self) -> u64 {
        self.state.total_events_processed
    }

    pub(crate) fn tracked_sources(&self) -> usize {
        self.state.sources.len()
    }

    fn ensure_source_slot(&mut self, source_ip: IpAddr, now: u64) -> Result<(), AgentError> {
        if self.state.sources.contains_key(&source_ip) {
            return Ok(());
        }

        if self.state.sources.len() == MAX_TRACKED_SOURCES {
            let mut oldest_source = None;
            let mut oldest_activity = u64::MAX;

            for (candidate_ip, source_state) in &self.state.sources {
                if source_state.last_activity < oldest_activity {
                    oldest_activity = source_state.last_activity;
                    oldest_source = Some(*candidate_ip);
                }
            }

            let evicted_source = oldest_source.ok_or_else(|| {
                context_error(
                    "operation=ensure_source_slot; source table reported full without candidates",
                    "sources",
                )
            })?;
            let _ = self.state.sources.remove(&evicted_source);
        }

        self.state
            .sources
            .insert(source_ip, SourceState::new(now))
            .map_err(|_| {
                crate::failures::buffer_error(
                    "operation=ensure_source_slot; fixed-capacity source table is full",
                    "sources",
                )
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use palisade_config::{ActionType, ResponseCondition, ResponseRule, Severity};
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};

    fn hardened_policy() -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.scoring.max_events_in_memory = MAX_HISTORY_DEPTH;
        policy
    }

    fn artifact_event(source_ip: IpAddr, timestamp_secs: u64) -> EventContext<'static> {
        EventContext {
            source_ip,
            confidence: 90.0,
            timestamp_secs,
            current_hour: 12,
            kind: EventKind::ArtifactAccess {
                artifact_id: "fake-aws-credentials",
                artifact_tag: "tag-1",
            },
        }
    }

    #[test]
    fn test_rejects_unrepresentable_default_policy() {
        assert!(CorrelationEngine::from_policy(&PolicyConfig::default()).is_err());
    }

    #[test]
    fn test_event_updates_last_outcome() {
        let mut engine = CorrelationEngine::from_policy(&hardened_policy()).unwrap();
        let event = artifact_event("10.0.0.1".parse().unwrap(), 10);

        engine.process(event).unwrap();

        assert!(engine.has_last_result());
        assert!(engine.last_score() > 0.0);
        assert_eq!(engine.tracked_sources(), 1);
    }

    #[test]
    fn test_cooldown_tracking_suppresses_action() {
        let mut policy = hardened_policy();
        policy.scoring.alert_threshold = 0.0;
        policy.scoring.weights.artifact_access = 60.0;

        let mut engine = CorrelationEngine::from_policy(&policy).unwrap();
        let source_ip: IpAddr = "10.0.0.2".parse().unwrap();

        let first = EventContext::new(
            source_ip,
            "session-1",
            90.0,
            EventKind::ArtifactAccess {
                artifact_id: "fake-cred",
                artifact_tag: "tag-2",
            },
        )
        .unwrap();
        engine.process(first).unwrap();
        assert_eq!(engine.last_action_code(), ACTION_ALERT);
        assert!(!engine.last_on_cooldown());

        engine.record_response_for_source(source_ip).unwrap();

        let second = EventContext::new(
            source_ip,
            "session-2",
            90.0,
            EventKind::ArtifactAccess {
                artifact_id: "fake-cred",
                artifact_tag: "tag-3",
            },
        )
        .unwrap();
        engine.process(second).unwrap();
        assert!(engine.last_on_cooldown());
        assert_eq!(engine.last_action_code(), ACTION_LOG);
    }

    #[test]
    fn test_not_parented_by_blocks_destructive_action() {
        let mut policy = hardened_policy();
        policy.scoring.alert_threshold = 0.0;
        policy.scoring.weights.ancestry_suspicious = 70.0;
        policy.response.rules = vec![
            ResponseRule {
                severity: Severity::Low,
                conditions: vec![],
                action: ActionType::Log,
            },
            ResponseRule {
                severity: Severity::Medium,
                conditions: vec![],
                action: ActionType::Alert,
            },
            ResponseRule {
                severity: Severity::High,
                conditions: vec![ResponseCondition::NotParentedBy {
                    process_name: "palisade-agent".to_string(),
                }],
                action: ActionType::KillProcess,
            },
            ResponseRule {
                severity: Severity::Critical,
                conditions: vec![],
                action: ActionType::IsolateHost,
            },
        ];

        let mut engine = CorrelationEngine::from_policy(&policy).unwrap();
        let source_ip: IpAddr = "10.0.0.3".parse().unwrap();

        let blocked = EventContext {
            source_ip,
            confidence: 95.0,
            timestamp_secs: 100,
            current_hour: 12,
            kind: EventKind::SuspiciousAncestry {
                process_chain: &["palisade-agent", "cmd.exe"],
            },
        };
        engine.process(blocked).unwrap();
        assert_eq!(engine.last_action_code(), ACTION_LOG);

        let allowed = EventContext {
            source_ip,
            confidence: 95.0,
            timestamp_secs: 101,
            current_hour: 12,
            kind: EventKind::SuspiciousAncestry {
                process_chain: &["systemd", "cmd.exe"],
            },
        };
        engine.process(allowed).unwrap();
        assert_eq!(engine.last_action_code(), ACTION_KILL_PROCESS);
    }

    #[test]
    fn test_custom_conditions_are_rejected() {
        let mut policy = hardened_policy();
        policy.response.rules[0].conditions = vec![ResponseCondition::Custom {
            name: "geo_allowlist".to_string(),
            params: HashMap::new(),
        }];
        policy.registered_custom_conditions = HashSet::from(["geo_allowlist".to_string()]);

        assert!(CorrelationEngine::from_policy(&policy).is_err());
    }

    #[test]
    fn test_source_eviction_prefers_oldest_activity() {
        let mut engine = CorrelationEngine::from_policy(&hardened_policy()).unwrap();
        let first_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for index in 0..MAX_TRACKED_SOURCES {
            let source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, (index + 1) as u8));
            engine
                .process(artifact_event(source_ip, index as u64 + 1))
                .unwrap();
        }

        engine.process(artifact_event(first_ip, 10_000)).unwrap();

        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
        engine.process(artifact_event(new_ip, 20_000)).unwrap();

        assert!(engine.state.sources.contains_key(&first_ip));
        assert!(engine.state.sources.contains_key(&new_ip));
        assert!(!engine.state.sources.contains_key(&second_ip));
    }
}
