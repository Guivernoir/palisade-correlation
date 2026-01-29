//! Event types for the correlation engine.
//!
//! These events are derived from telemetry, errors, and configuration changes
//! in the Palisade honeypot system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Unique identifier for correlation events
pub type EventId = u64;

/// Unique identifier for correlation sessions
pub type SessionId = String;

/// Security event that can be correlated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub id: EventId,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Source IP address
    pub source_ip: IpAddr,
    
    /// Session/correlation identifier
    pub session_id: SessionId,
    
    /// Event type
    pub event_type: EventType,
    
    /// Event severity
    pub severity: EventSeverity,
    
    /// Confidence score (0.0 - 100.0)
    pub confidence: f64,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of security events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// Artifact access (honeytoken, decoy file, etc.)
    ArtifactAccess {
        artifact_id: String,
        artifact_tag: String,
    },
    
    /// Suspicious process detected
    SuspiciousProcess {
        process_name: String,
        pid: u32,
    },
    
    /// Rapid enumeration detected
    RapidEnumeration {
        target_count: usize,
        time_window_secs: u64,
    },
    
    /// Off-hours activity
    OffHoursActivity {
        hour: u8,
    },
    
    /// Suspicious process ancestry
    SuspiciousAncestry {
        process_chain: Vec<String>,
    },
    
    /// Authentication failure
    AuthenticationFailure {
        username: String,
        method: String,
    },
    
    /// Path traversal attempt
    PathTraversal {
        attempted_path: String,
    },
    
    /// SQL injection attempt
    SqlInjection {
        payload: String,
    },
    
    /// Command injection attempt
    CommandInjection {
        command: String,
    },
    
    /// Configuration change
    ConfigurationChange {
        field: String,
        old_value: String,
        new_value: String,
    },
    
    /// Error event (from palisade-errors)
    ErrorEvent {
        error_code: String,
        operation: String,
        category: String,
    },
}

/// Event severity levels (aligned with palisade-config)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Low severity (< 30 points)
    Low,
    /// Medium severity (30-60 points)
    Medium,
    /// High severity (60-80 points)
    High,
    /// Critical severity (> 80 points)
    Critical,
}

impl EventSeverity {
    /// Convert a numeric score to severity level
    pub fn from_score(score: f64) -> Self {
        if score < 30.0 {
            Self::Low
        } else if score < 60.0 {
            Self::Medium
        } else if score < 80.0 {
            Self::High
        } else {
            Self::Critical
        }
    }
    
    /// Get numeric threshold for this severity
    pub fn threshold(&self) -> f64 {
        match self {
            Self::Low => 0.0,
            Self::Medium => 30.0,
            Self::High => 60.0,
            Self::Critical => 80.0,
        }
    }
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        id: EventId,
        source_ip: IpAddr,
        session_id: SessionId,
        event_type: EventType,
    ) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            source_ip,
            session_id,
            event_type,
            severity: EventSeverity::Low,
            confidence: 50.0,
            metadata: HashMap::new(),
        }
    }
    
    /// Add metadata to the event
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
    
    /// Set event severity
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }
    
    /// Set confidence score
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 100.0);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_severity_from_score() {
        assert_eq!(EventSeverity::from_score(10.0), EventSeverity::Low);
        assert_eq!(EventSeverity::from_score(40.0), EventSeverity::Medium);
        assert_eq!(EventSeverity::from_score(70.0), EventSeverity::High);
        assert_eq!(EventSeverity::from_score(90.0), EventSeverity::Critical);
    }
    
    #[test]
    fn test_event_creation() {
        let event = SecurityEvent::new(
            1,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "session-123".to_string(),
            EventType::ArtifactAccess {
                artifact_id: "fake-aws-creds".to_string(),
                artifact_tag: "tag-abc".to_string(),
            },
        )
        .with_metadata("user_agent", "curl/7.68.0")
        .with_confidence(75.0);
        
        assert_eq!(event.confidence, 75.0);
        assert_eq!(event.metadata.get("user_agent").unwrap(), "curl/7.68.0");
    }
}