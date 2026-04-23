//! Fixed-capacity runtime state for the hardened correlation engine.

use crate::events::{EventContext, EventKind, MAX_ANCESTRY_DEPTH, ObservedSignal};
use crate::failures::buffer_error;
use crate::matching::{copy_str_to_buffer, hash_ascii_case_insensitive};
use crate::patterns::{KILL_CHAIN_NONE, MAX_PATTERNS_PER_RESULT, MAX_PATTERNS_PER_SOURCE};
use heapless::{Deque, String as HString, Vec as HVec, index_map::FnvIndexMap};
use std::net::IpAddr;
use zeroize::Zeroize;

pub(crate) const MAX_TRACKED_SOURCES: usize = 128;
pub(crate) const MAX_HISTORY_DEPTH: usize = 64;
pub(crate) const MAX_SUSPICIOUS_PROCESSES: usize = 128;
pub(crate) const MAX_SUSPICIOUS_PATTERNS: usize = 128;
pub(crate) const MAX_RESPONSE_CONDITIONS: usize = 8;
pub(crate) const MAX_ACTION_PATH_LEN: usize = 256;
pub(crate) const MAX_IP_TEXT_LEN: usize = 45;

pub(crate) const SEVERITY_INFORMATIONAL: u8 = 0;
pub(crate) const SEVERITY_LOW: u8 = 1;
pub(crate) const SEVERITY_MEDIUM: u8 = 2;
pub(crate) const SEVERITY_HIGH: u8 = 3;
pub(crate) const SEVERITY_CRITICAL: u8 = 4;

pub(crate) const ACTION_LOG: u8 = 0;
pub(crate) const ACTION_ALERT: u8 = 1;
pub(crate) const ACTION_KILL_PROCESS: u8 = 2;
pub(crate) const ACTION_ISOLATE_HOST: u8 = 3;
pub(crate) const ACTION_CUSTOM_SCRIPT: u8 = 4;

pub(crate) struct CorrelationState {
    pub(crate) sources: FnvIndexMap<IpAddr, SourceState, MAX_TRACKED_SOURCES>,
    pub(crate) last_outcome: LastOutcome,
    pub(crate) total_events_processed: u64,
}

impl CorrelationState {
    pub(crate) fn new() -> Self {
        Self {
            sources: FnvIndexMap::new(),
            last_outcome: LastOutcome::new(),
            total_events_processed: 0,
        }
    }
}

pub(crate) struct SourceState {
    pub(crate) history: Deque<ObservedSignal, MAX_HISTORY_DEPTH>,
    pub(crate) patterns: HVec<u16, MAX_PATTERNS_PER_SOURCE>,
    recent_ancestry_hashes: HVec<u64, MAX_ANCESTRY_DEPTH>,
    pub(crate) last_activity: u64,
    last_ancestry_secs: u64,
    pub(crate) kill_chain_stage_code: u8,
    pub(crate) last_response_secs: u64,
    pub(crate) destructive_actions_in_window: usize,
}

impl SourceState {
    pub(crate) fn new(now: u64) -> Self {
        Self {
            history: Deque::new(),
            patterns: HVec::new(),
            recent_ancestry_hashes: HVec::new(),
            last_activity: now,
            last_ancestry_secs: 0,
            kill_chain_stage_code: KILL_CHAIN_NONE,
            last_response_secs: 0,
            destructive_actions_in_window: 0,
        }
    }

    pub(crate) fn record_observed(
        &mut self,
        observed_kind: u8,
        timestamp_secs: u64,
        max_events_per_source: usize,
        correlation_window_secs: u64,
    ) -> Result<(), palisade_errors::AgentError> {
        self.prune_history(timestamp_secs, correlation_window_secs);
        if self.history.is_empty() {
            self.reset_incident();
        }

        while self.history.len() >= max_events_per_source {
            let _ = self.history.pop_front();
        }

        if self.history.len() == MAX_HISTORY_DEPTH {
            let _ = self.history.pop_front();
        }

        self.history
            .push_back(ObservedSignal::new(observed_kind, timestamp_secs))
            .map_err(|_| {
                buffer_error(
                    "operation=record_observed; fixed-capacity history buffer is full",
                    "history",
                )
            })?;

        Ok(())
    }

    pub(crate) fn update_ancestry_context(
        &mut self,
        event: &EventContext<'_>,
    ) -> Result<(), palisade_errors::AgentError> {
        let EventKind::SuspiciousAncestry { process_chain } = &event.kind else {
            return Ok(());
        };

        self.clear_ancestry_context();
        for process_name in *process_chain {
            self.recent_ancestry_hashes
                .push(hash_ascii_case_insensitive(process_name))
                .map_err(|_| {
                    buffer_error(
                        "operation=update_ancestry_context; ancestry buffer exceeded fixed-capacity limit",
                        "process_chain",
                    )
                })?;
        }

        self.last_ancestry_secs = event.timestamp_secs;
        Ok(())
    }

    pub(crate) fn distinct_signal_types_within(&self, now: u64, window_secs: u64) -> usize {
        let mut distinct = HVec::<u8, 16>::new();

        for entry in &self.history {
            if now.saturating_sub(entry.timestamp_secs) > window_secs {
                continue;
            }

            if !distinct.contains(&entry.observed_kind) {
                let _ = distinct.push(entry.observed_kind);
            }
        }

        distinct.len()
    }

    pub(crate) fn event_count_within(&self, now: u64, window_secs: u64) -> usize {
        self.history
            .iter()
            .filter(|entry| now.saturating_sub(entry.timestamp_secs) <= window_secs)
            .count()
    }

    pub(crate) fn recent_ancestry_contains(
        &self,
        process_name_hash: u64,
        now: u64,
        window_secs: u64,
    ) -> Option<bool> {
        if self.last_ancestry_secs == 0
            || now.saturating_sub(self.last_ancestry_secs) > window_secs
            || self.recent_ancestry_hashes.is_empty()
        {
            return None;
        }

        Some(self.recent_ancestry_hashes.contains(&process_name_hash))
    }

    pub(crate) fn reset_incident(&mut self) {
        self.patterns.clear();
        self.kill_chain_stage_code = KILL_CHAIN_NONE;
        self.destructive_actions_in_window = 0;
        self.clear_ancestry_context();
    }

    pub(crate) fn prune_history(&mut self, now: u64, correlation_window_secs: u64) {
        while let Some(entry) = self.history.front() {
            if now.saturating_sub(entry.timestamp_secs) <= correlation_window_secs {
                break;
            }
            let _ = self.history.pop_front();
        }
    }

    fn clear_ancestry_context(&mut self) {
        self.recent_ancestry_hashes.clear();
        self.last_ancestry_secs = 0;
    }
}

pub(crate) struct LastOutcome {
    pub(crate) has_result: bool,
    pub(crate) score: f64,
    pub(crate) severity_code: u8,
    pub(crate) action: ActionDescriptor,
    pub(crate) on_cooldown: bool,
    pub(crate) kill_chain_stage_code: u8,
    pub(crate) pattern_codes: HVec<u16, MAX_PATTERNS_PER_RESULT>,
    pub(crate) source_ip: Option<IpAddr>,
}

impl LastOutcome {
    pub(crate) fn new() -> Self {
        Self {
            has_result: false,
            score: 0.0,
            severity_code: SEVERITY_INFORMATIONAL,
            action: ActionDescriptor::new(),
            on_cooldown: false,
            kill_chain_stage_code: KILL_CHAIN_NONE,
            pattern_codes: HVec::new(),
            source_ip: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record(
        &mut self,
        source_ip: IpAddr,
        score: f64,
        severity_code: u8,
        action: ActionDescriptor,
        on_cooldown: bool,
        kill_chain_stage_code: u8,
        pattern_codes: &[u16],
    ) {
        self.has_result = true;
        self.score = score;
        self.severity_code = severity_code;
        self.action.replace_from(&action);
        self.on_cooldown = on_cooldown;
        self.kill_chain_stage_code = kill_chain_stage_code;
        self.pattern_codes.clear();
        for pattern_code in pattern_codes {
            let _ = self.pattern_codes.push(*pattern_code);
        }
        self.source_ip = Some(source_ip);
    }
}

pub(crate) struct ActionDescriptor {
    pub(crate) code: u8,
    script_path: HString<MAX_ACTION_PATH_LEN>,
}

impl ActionDescriptor {
    pub(crate) fn new() -> Self {
        Self {
            code: ACTION_LOG,
            script_path: HString::new(),
        }
    }

    pub(crate) fn replace_from(&mut self, next: &ActionDescriptor) {
        self.code = next.code;
        self.script_path.zeroize();
        self.script_path.clear();
        let _ = self.script_path.push_str(next.script_path.as_str());
    }

    pub(crate) fn is_destructive(&self) -> bool {
        matches!(
            self.code,
            ACTION_KILL_PROCESS | ACTION_ISOLATE_HOST | ACTION_CUSTOM_SCRIPT
        )
    }

    pub(crate) fn write_script_path(&self, out: &mut [u8]) -> usize {
        copy_str_to_buffer(self.script_path.as_str(), out)
    }

    pub(crate) fn set_script_path(&mut self, path: &str) {
        let _ = self.script_path.push_str(path);
    }
}
