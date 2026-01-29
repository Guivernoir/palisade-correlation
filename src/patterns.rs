//! Attack pattern detection and classification.
//!
//! This module analyzes sequences of events to identify known attack patterns
//! and techniques, inspired by the MITRE ATT&CK framework.

use crate::events::{EventType, SecurityEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Known attack patterns
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackPattern {
    /// T1110 - Brute Force
    BruteForce,
    
    /// T1083 - File and Directory Discovery
    Discovery,
    
    /// T1078 - Valid Accounts (credential access)
    CredentialAccess,
    
    /// T1190 - Exploit Public-Facing Application
    Exploitation,
    
    /// T1210 - Exploitation of Remote Services
    LateralMovement,
    
    /// T1498 - Network Denial of Service
    DenialOfService,
    
    /// T1071 - Application Layer Protocol (C2)
    CommandAndControl,
    
    /// T1003 - OS Credential Dumping
    CredentialDumping,
    
    /// T1059 - Command and Scripting Interpreter
    Execution,
    
    /// T1057 - Process Discovery
    ProcessDiscovery,
    
    /// Custom: Honeypot reconnaissance
    HoneypotProbing,
}

impl AttackPattern {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::BruteForce => "Brute force authentication attempts",
            Self::Discovery => "File and directory enumeration",
            Self::CredentialAccess => "Attempting to access credentials",
            Self::Exploitation => "Exploiting application vulnerabilities",
            Self::LateralMovement => "Moving laterally across network",
            Self::DenialOfService => "Denial of service attack",
            Self::CommandAndControl => "Command and control communication",
            Self::CredentialDumping => "Dumping credentials from memory",
            Self::Execution => "Executing malicious commands",
            Self::ProcessDiscovery => "Enumerating running processes",
            Self::HoneypotProbing => "Systematic honeypot reconnaissance",
        }
    }
    
    /// Get MITRE ATT&CK technique ID (where applicable)
    pub fn mitre_id(&self) -> Option<&'static str> {
        match self {
            Self::BruteForce => Some("T1110"),
            Self::Discovery => Some("T1083"),
            Self::CredentialAccess => Some("T1078"),
            Self::Exploitation => Some("T1190"),
            Self::LateralMovement => Some("T1210"),
            Self::DenialOfService => Some("T1498"),
            Self::CommandAndControl => Some("T1071"),
            Self::CredentialDumping => Some("T1003"),
            Self::Execution => Some("T1059"),
            Self::ProcessDiscovery => Some("T1057"),
            Self::HoneypotProbing => None,
        }
    }
}

/// Attack campaign - a sequence of correlated attack patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCampaign {
    /// Campaign identifier
    pub id: String,
    
    /// Source IP
    pub source_ip: String,
    
    /// Start time (Unix timestamp)
    pub start_time: u64,
    
    /// Last activity time (Unix timestamp)
    pub last_activity: u64,
    
    /// Detected patterns
    pub patterns: Vec<AttackPattern>,
    
    /// Event count
    pub event_count: usize,
    
    /// Aggregate confidence score
    pub confidence: f64,
    
    /// Kill chain stage (if determinable)
    pub kill_chain_stage: Option<KillChainStage>,
}

/// Cyber kill chain stages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillChainStage {
    /// Reconnaissance
    Reconnaissance,
    
    /// Weaponization
    Weaponization,
    
    /// Delivery
    Delivery,
    
    /// Exploitation
    Exploitation,
    
    /// Installation
    Installation,
    
    /// Command & Control
    CommandAndControl,
    
    /// Actions on Objectives
    ActionsOnObjectives,
}

/// Pattern detector analyzes event sequences
pub struct PatternDetector {
    /// Event history by source IP (bounded size)
    history: HashMap<String, Vec<EventType>>,
    
    /// Maximum events to track per IP
    max_events_per_ip: usize,
}

impl PatternDetector {
    /// Create a new pattern detector
    pub fn new(max_events_per_ip: usize) -> Self {
        Self {
            history: HashMap::new(),
            max_events_per_ip,
        }
    }
    
    /// Analyze an event and detect patterns
    pub fn analyze(&mut self, event: &SecurityEvent) -> Vec<AttackPattern> {
        let source = event.source_ip.to_string();
        
        // Update history (bounded)
        let history = self.history.entry(source.clone()).or_insert_with(Vec::new);
        history.push(event.event_type.clone());
        
        if history.len() > self.max_events_per_ip {
            history.remove(0);
        }
        
        // Clone history to avoid borrow checker issues
        let history_snapshot = history.clone();
        
        // Detect patterns using the snapshot
        let mut patterns = Vec::new();
        
        // Check for brute force
        if Self::is_brute_force_static(&history_snapshot) {
            patterns.push(AttackPattern::BruteForce);
        }
        
        // Check for discovery
        if Self::is_discovery_static(&history_snapshot) {
            patterns.push(AttackPattern::Discovery);
        }
        
        // Check for credential access
        if Self::is_credential_access_static(&event.event_type) {
            patterns.push(AttackPattern::CredentialAccess);
        }
        
        // Check for exploitation attempts
        if Self::is_exploitation_static(&event.event_type) {
            patterns.push(AttackPattern::Exploitation);
        }
        
        // Check for credential dumping
        if Self::is_credential_dumping_static(&event.event_type) {
            patterns.push(AttackPattern::CredentialDumping);
        }
        
        // Check for DoS
        if Self::is_dos_static(&history_snapshot) {
            patterns.push(AttackPattern::DenialOfService);
        }
        
        // Check for honeypot probing
        if Self::is_honeypot_probing_static(&history_snapshot) {
            patterns.push(AttackPattern::HoneypotProbing);
        }
        
        patterns
    }
    
    /// Detect brute force pattern
    fn is_brute_force_static(history: &[EventType]) -> bool {
        // 5+ auth failures in recent history
        history.iter()
            .filter(|e| matches!(e, EventType::AuthenticationFailure { .. }))
            .count() >= 5
    }
    
    /// Detect discovery pattern
    fn is_discovery_static(history: &[EventType]) -> bool {
        // Rapid enumeration or multiple path traversals
        let rapid_enum = history.iter()
            .any(|e| matches!(e, EventType::RapidEnumeration { .. }));
        
        let path_traversals = history.iter()
            .filter(|e| matches!(e, EventType::PathTraversal { .. }))
            .count();
        
        rapid_enum || path_traversals >= 3
    }
    
    /// Detect credential access
    fn is_credential_access_static(event_type: &EventType) -> bool {
        matches!(event_type, EventType::ArtifactAccess { artifact_id, .. }
            if artifact_id.contains("cred") || artifact_id.contains("key") || artifact_id.contains("token"))
    }
    
    /// Detect exploitation attempts
    fn is_exploitation_static(event_type: &EventType) -> bool {
        matches!(event_type, 
            EventType::SqlInjection { .. } |
            EventType::CommandInjection { .. } |
            EventType::PathTraversal { .. }
        )
    }
    
    /// Detect credential dumping
    fn is_credential_dumping_static(event_type: &EventType) -> bool {
        if let EventType::SuspiciousProcess { process_name, .. } = event_type {
            let name_lower = process_name.to_lowercase();
            name_lower.contains("mimikatz") ||
                name_lower.contains("procdump") ||
                name_lower.contains("lazagne") ||
                name_lower.contains("secretsdump")
        } else {
            false
        }
    }
    
    /// Detect DoS pattern
    fn is_dos_static(history: &[EventType]) -> bool {
        // Check if history is filled with rapid enumeration or errors
        if history.len() < 10 {
            return false;
        }
        
        // More than 80% of recent events are rapid enumeration
        let rapid_count = history.iter()
            .filter(|e| matches!(e, EventType::RapidEnumeration { .. }))
            .count();
        
        (rapid_count as f64 / history.len() as f64) > 0.8
    }
    
    /// Detect honeypot probing (systematic testing)
    fn is_honeypot_probing_static(history: &[EventType]) -> bool {
        // Diverse event types suggest systematic probing
        let unique_types = history.iter()
            .map(|e| std::mem::discriminant(e))
            .collect::<std::collections::HashSet<_>>();
        
        unique_types.len() >= 4 && history.len() >= 8
    }
    
    /// Infer kill chain stage from patterns
    pub fn infer_kill_chain_stage(patterns: &[AttackPattern]) -> Option<KillChainStage> {
        if patterns.contains(&AttackPattern::HoneypotProbing) 
            || patterns.contains(&AttackPattern::Discovery) {
            Some(KillChainStage::Reconnaissance)
        } else if patterns.contains(&AttackPattern::Exploitation) {
            Some(KillChainStage::Exploitation)
        } else if patterns.contains(&AttackPattern::CredentialDumping) {
            Some(KillChainStage::ActionsOnObjectives)
        } else if patterns.contains(&AttackPattern::BruteForce) {
            Some(KillChainStage::Delivery)
        } else {
            None
        }
    }
    
    /// Clear history for a specific IP
    pub fn clear_history(&mut self, source_ip: &str) {
        self.history.remove(source_ip);
    }
    
    /// Get total tracked IPs
    pub fn tracked_ip_count(&self) -> usize {
        self.history.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    
    fn create_test_event(event_type: EventType) -> SecurityEvent {
        SecurityEvent::new(
            1,
            "192.168.1.100".parse::<IpAddr>().unwrap(),
            "test-session".to_string(),
            event_type,
        )
    }
    
    #[test]
    fn test_brute_force_detection() {
        let mut detector = PatternDetector::new(100);
        
        // Simulate 5 auth failures
        for _ in 0..5 {
            let event = create_test_event(EventType::AuthenticationFailure {
                username: "admin".to_string(),
                method: "password".to_string(),
            });
            
            let patterns = detector.analyze(&event);
            
            // Should detect brute force on or after 5th attempt
            if detector.history.get(&event.source_ip.to_string()).unwrap().len() >= 5 {
                assert!(patterns.contains(&AttackPattern::BruteForce));
            }
        }
    }
    
    #[test]
    fn test_credential_access_detection() {
        let mut detector = PatternDetector::new(100);
        
        let event = create_test_event(EventType::ArtifactAccess {
            artifact_id: "fake-aws-credentials".to_string(),
            artifact_tag: "tag-123".to_string(),
        });
        
        let patterns = detector.analyze(&event);
        assert!(patterns.contains(&AttackPattern::CredentialAccess));
    }
    
    #[test]
    fn test_kill_chain_inference() {
        let patterns = vec![
            AttackPattern::Discovery,
            AttackPattern::HoneypotProbing,
        ];
        
        let stage = PatternDetector::infer_kill_chain_stage(&patterns);
        assert_eq!(stage, Some(KillChainStage::Reconnaissance));
    }
}