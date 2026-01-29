//! Integration with palisade-errors.
//!
//! This module provides utilities for converting AgentErrors into
//! correlation events for analysis.

use crate::events::{EventSeverity, EventType, SecurityEvent};
use palisade_errors::AgentError;
use std::net::IpAddr;

/// Convert an AgentError into a SecurityEvent
pub fn error_to_event(
    error: &AgentError,
    source_ip: IpAddr,
    session_id: String,
) -> SecurityEvent {
    let event_type = EventType::ErrorEvent {
        error_code: error.code().to_string(),
        operation: error.internal_log().operation().to_string(),
        category: "Unknown".to_string(), // ErrorCategory not available in public API
    };
    
    // Map error severity to event severity based on retryability
    let severity = if error.is_retryable() {
        EventSeverity::Low
    } else {
        EventSeverity::Medium
    };
    
    // Calculate confidence based on error characteristics
    let confidence = if error.is_retryable() {
        // Transient errors are less indicative of attacks
        40.0
    } else {
        // Permanent errors might indicate attack attempts
        70.0
    };
    
    // Extract metadata before creating event to avoid borrow issues
    let mut metadata_entries = Vec::new();
    error.with_internal_log(|log| {
        metadata_entries.push(("operation".to_string(), log.operation().to_string()));
        metadata_entries.push(("error_code".to_string(), log.code().to_string()));
        
        for (key, value) in log.metadata() {
            metadata_entries.push((key.to_string(), value.as_str().to_string()));
        }
    });
    
    // Create event with extracted metadata
    let mut event = SecurityEvent::new(0, source_ip, session_id, event_type)
        .with_severity(severity)
        .with_confidence(confidence);
    
    // Add all metadata
    for (key, value) in metadata_entries {
        event = event.with_metadata(key, value);
    }
    
    event
}

/// Detect suspicious error patterns that might indicate attacks
pub fn detect_attack_from_error(error: &AgentError) -> Option<EventType> {
    error.with_internal_log(|log| {
        let operation = log.operation();
        let details = log.details();
        
        // Check for SQL injection patterns
        if details.contains("SQL") || details.contains("injection") {
            return Some(EventType::SqlInjection {
                payload: details.to_string(),
            });
        }
        
        // Check for command injection
        if details.contains("command") && (details.contains("injection") || details.contains("exec")) {
            return Some(EventType::CommandInjection {
                command: details.to_string(),
            });
        }
        
        // Check for path traversal
        if let Some(sensitive) = log.source_sensitive() {
            if sensitive.contains("../") || sensitive.contains("..\\") {
                return Some(EventType::PathTraversal {
                    attempted_path: sensitive.to_string(),
                });
            }
        }
        
        // Check for authentication failures
        if operation.contains("auth") || operation.contains("login") {
            if details.contains("failed") || details.contains("denied") {
                return Some(EventType::AuthenticationFailure {
                    username: extract_username(log.metadata()).unwrap_or_else(|| "unknown".to_string()),
                    method: extract_auth_method(log.metadata()).unwrap_or_else(|| "unknown".to_string()),
                });
            }
        }
        
        None
    })
}

/// Extract username from error metadata
fn extract_username(metadata: &[(&str, palisade_errors::ContextField)]) -> Option<String> {
    metadata.iter()
        .find(|(key, _)| *key == "username" || *key == "user")
        .map(|(_, value)| value.as_str().to_string())
}

/// Extract authentication method from error metadata
fn extract_auth_method(metadata: &[(&str, palisade_errors::ContextField)]) -> Option<String> {
    metadata.iter()
        .find(|(key, _)| *key == "auth_method" || *key == "method")
        .map(|(_, value)| value.as_str().to_string())
}

/// Create enhanced event from error with attack detection
pub fn enhanced_event_from_error(
    error: &AgentError,
    source_ip: IpAddr,
    session_id: String,
) -> SecurityEvent {
    // Try to detect specific attack type
    if let Some(attack_type) = detect_attack_from_error(error) {
        // Extract metadata before creating event to avoid borrow issues
        let error_code = error.code().to_string();
        let operation = error.internal_log().operation().to_string();
        
        let event = SecurityEvent::new(0, source_ip, session_id, attack_type)
            .with_confidence(85.0)
            .with_metadata("error_code", error_code)
            .with_metadata("operation", operation);
        
        return event;
    }
    
    // Fall back to generic error event
    error_to_event(error, source_ip, session_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use palisade_errors::{definitions, AgentError};
    
    #[test]
    fn test_error_to_event() {
        let error = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "validate_input",
            "Validation failed"
        );
        
        let event = error_to_event(
            &error,
            "192.168.1.100".parse().unwrap(),
            "session-1".to_string(),
        );
        
        assert_eq!(event.source_ip.to_string(), "192.168.1.100");
        assert!(matches!(event.event_type, EventType::ErrorEvent { .. }));
    }
    
    #[test]
    fn test_sql_injection_detection() {
        let error = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "validate_query",
            "SQL injection detected"
        );
        
        let attack_type = detect_attack_from_error(&error);
        assert!(matches!(attack_type, Some(EventType::SqlInjection { .. })));
    }
    
    #[test]
    fn test_auth_failure_detection() {
        let error = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "authenticate_user",
            "Authentication failed"
        )
        .with_metadata("username", "admin")
        .with_metadata("auth_method", "password");
        
        let attack_type = detect_attack_from_error(&error);
        assert!(matches!(attack_type, Some(EventType::AuthenticationFailure { .. })));
    }
}