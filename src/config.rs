//! Integration with palisade-config.
//!
//! This module provides utilities for responding to configuration changes
//! and using cryptographic tags in correlation.

use crate::events::{EventType, SecurityEvent};
use palisade_config::{ConfigChange, PolicyChange, RootTag};
use std::net::IpAddr;

/// Convert a config change into a correlation event
pub fn config_change_to_event(
    change: &ConfigChange,
    source_ip: IpAddr,
    session_id: String,
) -> SecurityEvent {
    let event_type = match change {
        ConfigChange::RootTagChanged { old_hash, new_hash } => {
            EventType::ConfigurationChange {
                field: "root_tag".to_string(),
                old_value: old_hash.clone(),
                new_value: new_hash.clone(),
            }
        }
        ConfigChange::PathsChanged { added, removed } => {
            EventType::ConfigurationChange {
                field: "paths".to_string(),
                old_value: removed.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                new_value: added.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        }
        ConfigChange::CapabilitiesChanged { 
            field,
            old,
            new,
         } => {
            EventType::ConfigurationChange {
                field: field.to_string(),
                old_value: old.to_string(),
                new_value: new.to_string(),
            }
        }
    };
    
    SecurityEvent::new(0, source_ip, session_id, event_type)
        .with_confidence(60.0)
}

/// Convert a policy change into a correlation event
pub fn policy_change_to_event(
    change: &PolicyChange,
    source_ip: IpAddr,
    session_id: String,
) -> SecurityEvent {
    let event_type = match change {
        PolicyChange::ThresholdChanged { field, old, new } => {
            EventType::ConfigurationChange {
                field: field.clone(),
                old_value: old.to_string(),
                new_value: new.to_string(),
            }
        }
        PolicyChange::ResponseRulesChanged { old_count, new_count } => {
            EventType::ConfigurationChange {
                field: "response_rules".to_string(),
                old_value: old_count.to_string(),
                new_value: new_count.to_string(),
            }
        }
        PolicyChange::SuspiciousProcessesChanged { added, removed } => {
            EventType::ConfigurationChange {
                field: "suspicious_processes".to_string(),
                old_value: removed.join(", "),
                new_value: added.join(", "),
            }
        }
    };
    
    SecurityEvent::new(0, source_ip, session_id, event_type)
        .with_confidence(70.0)
}

/// Validate artifact tag and create event if mismatch detected
pub fn validate_artifact_tag(
    artifact_id: &str,
    observed_tag: &str,
    root_tag: &RootTag,
    hostname: &str,
    source_ip: IpAddr,
    session_id: String,
) -> Option<SecurityEvent> {
    // Derive expected tag
    let expected_tag = root_tag.derive_artifact_tag(hostname, artifact_id);
    let expected_tag_str = hex::encode(&expected_tag);
    
    // Check if observed tag matches
    if observed_tag != expected_tag_str {
        // Tag mismatch - potential tampering or correlation issue
        let event = SecurityEvent::new(
            0,
            source_ip,
            session_id,
            EventType::ArtifactAccess {
                artifact_id: artifact_id.to_string(),
                artifact_tag: observed_tag.to_string(),
            },
        )
        .with_metadata("tag_mismatch", "true")
        .with_metadata("expected_tag", &expected_tag_str[..16]) // First 16 chars
        .with_metadata("observed_tag", &observed_tag[..16.min(observed_tag.len())])
        .with_confidence(95.0); // High confidence - tag mismatch is serious
        
        return Some(event);
    }
    
    None
}

/// Create artifact access event with validated tag
pub fn artifact_access_event(
    artifact_id: &str,
    artifact_tag: &str,
    source_ip: IpAddr,
    session_id: String,
) -> SecurityEvent {
    SecurityEvent::new(
        0,
        source_ip,
        session_id,
        EventType::ArtifactAccess {
            artifact_id: artifact_id.to_string(),
            artifact_tag: artifact_tag.to_string(),
        },
    )
    .with_confidence(90.0)
}

/// Check if process is suspicious according to policy
pub fn check_suspicious_process(
    process_name: &str,
    pid: u32,
    policy: &palisade_config::PolicyConfig,
    source_ip: IpAddr,
    session_id: String,
) -> Option<SecurityEvent> {
    if policy.is_suspicious_process(process_name) {
        Some(
            SecurityEvent::new(
                0,
                source_ip,
                session_id,
                EventType::SuspiciousProcess {
                    process_name: process_name.to_string(),
                    pid,
                },
            )
            .with_confidence(85.0)
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use palisade_config::PolicyConfig;
    
    #[test]
    fn test_config_change_event() {
        let change = ConfigChange::RootTagChanged {
            old_hash: "1234567890abcdef".to_string(),
            new_hash: "fedcba0987654321".to_string(),
        };
        
        let event = config_change_to_event(
            &change,
            "127.0.0.1".parse().unwrap(),
            "session-1".to_string(),
        );
        
        assert!(matches!(event.event_type, EventType::ConfigurationChange { .. }));
    }
    
    #[test]
    fn test_suspicious_process_detection() {
        let mut policy = PolicyConfig::default();
        policy.deception.suspicious_processes.push("mimikatz".to_string());
        
        let event = check_suspicious_process(
            "mimikatz.exe",
            1234,
            &policy,
            "192.168.1.100".parse().unwrap(),
            "session-1".to_string(),
        );
        
        assert!(event.is_some());
        
        let no_event = check_suspicious_process(
            "chrome.exe",
            5678,
            &policy,
            "192.168.1.100".parse().unwrap(),
            "session-1".to_string(),
        );
        
        assert!(no_event.is_none());
    }
    
    #[test]
    fn test_artifact_tag_validation() {
        let root_tag = RootTag::generate();
        let hostname = "test-host";
        let artifact_id = "fake-aws-creds";
        
        // Derive correct tag
        let correct_tag = root_tag.derive_artifact_tag(hostname, artifact_id);
        let correct_tag_str = hex::encode(&correct_tag);
        
        // Validate with correct tag - should be None (no event)
        let no_event = validate_artifact_tag(
            artifact_id,
            &correct_tag_str,
            &root_tag,
            hostname,
            "192.168.1.100".parse().unwrap(),
            "session-1".to_string(),
        );
        assert!(no_event.is_none());
        
        // Validate with incorrect tag - should create event
        let mismatch_event = validate_artifact_tag(
            artifact_id,
            "wrong-tag-value",
            &root_tag,
            hostname,
            "192.168.1.100".parse().unwrap(),
            "session-1".to_string(),
        );
        assert!(mismatch_event.is_some());
        
        if let Some(event) = mismatch_event {
            assert_eq!(event.metadata.get("tag_mismatch").unwrap(), "true");
        }
    }
}