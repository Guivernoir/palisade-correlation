//! Fixed-code pattern detection helpers.

use crate::events::{
    EventContext, EventKind, OBSERVED_AUTHENTICATION_FAILURE, OBSERVED_NETWORK_PROBE,
    OBSERVED_PATH_TRAVERSAL, OBSERVED_RAPID_ENUMERATION, ObservedSignal,
};
use crate::matching::contains_ascii_case_insensitive;
use heapless::{Deque, Vec as HVec};

pub(crate) const MAX_PATTERNS_PER_RESULT: usize = 8;
pub(crate) const MAX_PATTERNS_PER_SOURCE: usize = 16;

pub(crate) const PATTERN_BRUTE_FORCE: u16 = 1110;
pub(crate) const PATTERN_DISCOVERY: u16 = 1083;
pub(crate) const PATTERN_CREDENTIAL_ACCESS: u16 = 1078;
pub(crate) const PATTERN_EXPLOITATION: u16 = 1190;
pub(crate) const PATTERN_LATERAL_MOVEMENT: u16 = 1210;
pub(crate) const PATTERN_DENIAL_OF_SERVICE: u16 = 1498;
pub(crate) const PATTERN_COMMAND_AND_CONTROL: u16 = 1071;
pub(crate) const PATTERN_CREDENTIAL_DUMPING: u16 = 1003;
pub(crate) const PATTERN_EXECUTION: u16 = 1059;
pub(crate) const PATTERN_PROCESS_DISCOVERY: u16 = 1057;
pub(crate) const PATTERN_HONEYPOT_PROBING: u16 = 9001;

pub(crate) const KILL_CHAIN_NONE: u8 = 0;
pub(crate) const KILL_CHAIN_RECONNAISSANCE: u8 = 1;
pub(crate) const KILL_CHAIN_WEAPONIZATION: u8 = 2;
pub(crate) const KILL_CHAIN_DELIVERY: u8 = 3;
pub(crate) const KILL_CHAIN_EXPLOITATION: u8 = 4;
pub(crate) const KILL_CHAIN_INSTALLATION: u8 = 5;
pub(crate) const KILL_CHAIN_COMMAND_AND_CONTROL: u8 = 6;
pub(crate) const KILL_CHAIN_ACTIONS_ON_OBJECTIVES: u8 = 7;

pub(crate) fn detect_patterns<const N: usize>(
    event: &EventContext<'_>,
    history: &Deque<ObservedSignal, N>,
    out: &mut HVec<u16, MAX_PATTERNS_PER_RESULT>,
) {
    if is_brute_force(history) {
        push_unique(out, PATTERN_BRUTE_FORCE);
    }

    if is_discovery(history) {
        push_unique(out, PATTERN_DISCOVERY);
    }

    if is_credential_access(&event.kind) {
        push_unique(out, PATTERN_CREDENTIAL_ACCESS);
    }

    if is_exploitation(&event.kind) {
        push_unique(out, PATTERN_EXPLOITATION);
    }

    if is_credential_dumping(&event.kind) {
        push_unique(out, PATTERN_CREDENTIAL_DUMPING);
    }

    if is_command_and_control(&event.kind) {
        push_unique(out, PATTERN_COMMAND_AND_CONTROL);
    }

    if is_execution(&event.kind) {
        push_unique(out, PATTERN_EXECUTION);
    }

    if is_process_discovery(&event.kind) {
        push_unique(out, PATTERN_PROCESS_DISCOVERY);
    }

    if is_dos(history) {
        push_unique(out, PATTERN_DENIAL_OF_SERVICE);
    }

    if is_honeypot_probing(history) {
        push_unique(out, PATTERN_HONEYPOT_PROBING);
    }
}

pub(crate) fn infer_kill_chain_stage(patterns: &[u16]) -> u8 {
    if contains_pattern(patterns, PATTERN_HONEYPOT_PROBING)
        || contains_pattern(patterns, PATTERN_DISCOVERY)
    {
        KILL_CHAIN_RECONNAISSANCE
    } else if contains_pattern(patterns, PATTERN_EXPLOITATION) {
        KILL_CHAIN_EXPLOITATION
    } else if contains_pattern(patterns, PATTERN_COMMAND_AND_CONTROL) {
        KILL_CHAIN_COMMAND_AND_CONTROL
    } else if contains_pattern(patterns, PATTERN_EXECUTION) {
        KILL_CHAIN_INSTALLATION
    } else if contains_pattern(patterns, PATTERN_CREDENTIAL_DUMPING) {
        KILL_CHAIN_ACTIONS_ON_OBJECTIVES
    } else if contains_pattern(patterns, PATTERN_BRUTE_FORCE) {
        KILL_CHAIN_DELIVERY
    } else {
        KILL_CHAIN_NONE
    }
}

pub(crate) fn contains_pattern(patterns: &[u16], target: u16) -> bool {
    patterns.contains(&target)
}

pub(crate) fn push_unique(out: &mut HVec<u16, MAX_PATTERNS_PER_RESULT>, code: u16) {
    if !out.contains(&code) {
        let _ = out.push(code);
    }
}

pub(crate) fn push_unique_campaign_pattern(
    out: &mut HVec<u16, MAX_PATTERNS_PER_SOURCE>,
    code: u16,
) {
    if !out.contains(&code) {
        let _ = out.push(code);
    }
}

fn is_brute_force<const N: usize>(history: &Deque<ObservedSignal, N>) -> bool {
    history
        .iter()
        .filter(|entry| entry.observed_kind == OBSERVED_AUTHENTICATION_FAILURE)
        .count()
        >= 5
}

fn is_discovery<const N: usize>(history: &Deque<ObservedSignal, N>) -> bool {
    let has_scan = history.iter().any(|entry| {
        entry.observed_kind == OBSERVED_RAPID_ENUMERATION
            || entry.observed_kind == OBSERVED_NETWORK_PROBE
    });

    let traversal_count = history
        .iter()
        .filter(|entry| entry.observed_kind == OBSERVED_PATH_TRAVERSAL)
        .count();

    has_scan || traversal_count >= 3
}

fn is_credential_access(event: &EventKind<'_>) -> bool {
    match event {
        EventKind::ArtifactAccess { artifact_id, .. } => {
            contains_ascii_case_insensitive(artifact_id, "cred")
                || contains_ascii_case_insensitive(artifact_id, "key")
                || contains_ascii_case_insensitive(artifact_id, "token")
        }
        _ => false,
    }
}

fn is_exploitation(event: &EventKind<'_>) -> bool {
    matches!(
        event,
        EventKind::SqlInjection { .. }
            | EventKind::CommandInjection { .. }
            | EventKind::PathTraversal { .. }
    )
}

fn is_credential_dumping(event: &EventKind<'_>) -> bool {
    match event {
        EventKind::SuspiciousProcess { process_name, .. } => {
            contains_ascii_case_insensitive(process_name, "mimikatz")
                || contains_ascii_case_insensitive(process_name, "procdump")
                || contains_ascii_case_insensitive(process_name, "lazagne")
                || contains_ascii_case_insensitive(process_name, "secretsdump")
        }
        _ => false,
    }
}

fn is_command_and_control(event: &EventKind<'_>) -> bool {
    matches!(event, EventKind::C2Communication { .. })
}

fn is_execution(event: &EventKind<'_>) -> bool {
    matches!(
        event,
        EventKind::CommandInjection { .. } | EventKind::MalwareDownload { .. }
    )
}

fn is_process_discovery(event: &EventKind<'_>) -> bool {
    matches!(
        event,
        EventKind::SuspiciousProcess { .. } | EventKind::SuspiciousAncestry { .. }
    )
}

fn is_dos<const N: usize>(history: &Deque<ObservedSignal, N>) -> bool {
    if history.len() < 10 {
        return false;
    }

    let scan_count = history
        .iter()
        .filter(|entry| {
            entry.observed_kind == OBSERVED_RAPID_ENUMERATION
                || entry.observed_kind == OBSERVED_NETWORK_PROBE
        })
        .count();

    (scan_count as f64 / history.len() as f64) > 0.8
}

fn is_honeypot_probing<const N: usize>(history: &Deque<ObservedSignal, N>) -> bool {
    if history.len() < 8 {
        return false;
    }

    let mut unique = HVec::<u8, 16>::new();
    for entry in history {
        if !unique.contains(&entry.observed_kind) {
            let _ = unique.push(entry.observed_kind);
        }
    }

    unique.len() >= 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventContext, EventKind};

    #[test]
    fn test_brute_force_pattern() {
        let mut history = Deque::<ObservedSignal, 16>::new();
        for _ in 0..5 {
            history
                .push_back(ObservedSignal::new(OBSERVED_AUTHENTICATION_FAILURE, 1))
                .unwrap();
        }

        let event = EventContext::new(
            "127.0.0.1".parse().unwrap(),
            "session-1",
            70.0,
            EventKind::AuthenticationFailure {
                username: "admin",
                method: "password",
            },
        )
        .unwrap();

        let mut detected = HVec::<u16, MAX_PATTERNS_PER_RESULT>::new();
        detect_patterns(&event, &history, &mut detected);
        assert!(detected.contains(&PATTERN_BRUTE_FORCE));
    }

    #[test]
    fn test_kill_chain_inference() {
        let patterns = [PATTERN_DISCOVERY, PATTERN_HONEYPOT_PROBING];
        assert_eq!(infer_kill_chain_stage(&patterns), KILL_CHAIN_RECONNAISSANCE);
    }
}
