//! # palisade-correlation
//!
//! Attack correlation engine for the Palisade honeypot system.
//!
//! This crate provides sophisticated correlation capabilities for detecting
//! and tracking attack campaigns across security events. It integrates seamlessly
//! with `palisade-errors` for error-driven detection and `palisade-config` for
//! policy-based response.
//!
//! ## Features
//!
//! - **Event Correlation**: Correlate disparate security events into coherent attack campaigns
//! - **Pattern Detection**: Identify attack patterns inspired by MITRE ATT&CK framework
//! - **Threat Scoring**: Calculate dynamic threat scores based on event characteristics
//! - **Policy Integration**: Leverage `palisade-config` policies for response decisions
//! - **Error Integration**: Convert `palisade-errors` into correlation events
//! - **Kill Chain Tracking**: Map attacks to cyber kill chain stages
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   Security Events                       │
//! │  (Errors, Config Changes, Telemetry, Artifacts)         │
//! └────────────────────┬────────────────────────────────────┘
//!                      │
//!                      ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Correlation Engine                         │
//! │  • Event Processing                                      │
//! │  • Pattern Detection                                     │
//! │  • Campaign Tracking                                     │
//! │  • Threat Scoring                                        │
//! └────────────────────┬────────────────────────────────────┘
//!                      │
//!                      ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Correlation Results                        │
//! │  • Attack Campaigns                                      │
//! │  • Threat Scores                                         │
//! │  • Recommended Actions                                   │
//! │  • Kill Chain Stages                                     │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,no_run
//! use palisade_correlation::{CorrelationEngine, SecurityEvent, EventType};
//! use palisade_config::PolicyConfig;
//! use std::net::IpAddr;
//!
//! // Initialize engine with policy
//! let policy = PolicyConfig::default();
//! let engine = CorrelationEngine::new(policy);
//!
//! // Create security event
//! let event = SecurityEvent::new(
//!     1,
//!     "192.168.1.100".parse::<IpAddr>().unwrap(),
//!     "session-abc".to_string(),
//!     EventType::ArtifactAccess {
//!         artifact_id: "fake-aws-creds".to_string(),
//!         artifact_tag: "tag-123".to_string(),
//!     },
//! ).with_confidence(85.0);
//!
//! // Correlate event
//! let result = engine.correlate(event).unwrap();
//!
//! println!("Threat Score: {}", result.score);
//! println!("Severity: {:?}", result.severity);
//! println!("Action: {:?}", result.action);
//! println!("Patterns: {:?}", result.patterns);
//! ```
//!
//! ## Integration with palisade-errors
//!
//! ```rust,no_run
//! use palisade_correlation::{CorrelationEngine, errors};
//! use palisade_errors::{AgentError, definitions};
//! use palisade_config::PolicyConfig;
//!
//! let engine = CorrelationEngine::new(PolicyConfig::default());
//!
//! // Create error
//! let error = AgentError::config(
//!     definitions::CFG_VALIDATION_FAILED,
//!     "authenticate",
//!     "Authentication failed"
//! );
//!
//! // Convert to event and correlate
//! let event = errors::enhanced_event_from_error(
//!     &error,
//!     "192.168.1.100".parse().unwrap(),
//!     "session-1".to_string(),
//! );
//!
//! let result = engine.correlate(event).unwrap();
//! ```
//!
//! ## Integration with palisade-config
//!
//! ```rust,no_run
//! use palisade_correlation::{CorrelationEngine, config};
//! use palisade_config::{PolicyConfig, ConfigChange};
//!
//! let engine = CorrelationEngine::new(PolicyConfig::default());
//!
//! // Detect suspicious process
//! let policy = engine.get_policy();
//! if let Some(event) = config::check_suspicious_process(
//!     "mimikatz.exe",
//!     1234,
//!     &policy,
//!     "192.168.1.100".parse().unwrap(),
//!     "session-1".to_string(),
//! ) {
//!     let result = engine.correlate(event).unwrap();
//!     println!("Suspicious process detected!");
//! }
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

// Re-export key types from dependencies
pub use palisade_config::{ActionType, PolicyConfig, Severity};
pub use palisade_errors::{AgentError, Result};

// Public modules
pub mod config;
pub mod engine;
pub mod errors;
pub mod events;
pub mod patterns;

// Re-export main types
pub use engine::{CorrelationEngine, CorrelationResult, EngineStats, Incident};
pub use events::{EventId, EventSeverity, EventType, SecurityEvent, SessionId};
pub use patterns::{AttackCampaign, AttackPattern, KillChainStage};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::net::IpAddr;
    
    #[test]
    fn test_full_correlation_pipeline() {
        // Create engine
        let policy = PolicyConfig::default();
        let engine = CorrelationEngine::new(policy);
        
        // Simulate attack sequence
        let source_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let session_id = "attack-session-1".to_string();
        
        // Step 1: Reconnaissance
        let event1 = SecurityEvent::new(
            0,
            source_ip,
            session_id.clone(),
            EventType::RapidEnumeration {
                target_count: 50,
                time_window_secs: 30,
            },
        ).with_confidence(70.0);
        
        let result1 = engine.correlate(event1).unwrap();
        assert!(result1.score > 0.0);
        
        // Step 2: Credential access
        let event2 = SecurityEvent::new(
            0,
            source_ip,
            session_id.clone(),
            EventType::ArtifactAccess {
                artifact_id: "fake-aws-credentials".to_string(),
                artifact_tag: "tag-abc".to_string(),
            },
        ).with_confidence(85.0);
        
        let result2 = engine.correlate(event2).unwrap();
        assert!(result2.score > result1.score); // Should increase
        assert!(result2.patterns.contains(&AttackPattern::CredentialAccess));
        
        // Step 3: Suspicious process
        let event3 = SecurityEvent::new(
            0,
            source_ip,
            session_id.clone(),
            EventType::SuspiciousProcess {
                process_name: "mimikatz.exe".to_string(),
                pid: 1234,
            },
        ).with_confidence(95.0);
        
        let result3 = engine.correlate(event3).unwrap();
        assert!(result3.score < result2.score);
        assert!(result3.patterns.contains(&AttackPattern::CredentialDumping));
        
        // Verify campaign tracking
        let campaigns = engine.get_active_campaigns();
        assert_eq!(campaigns.len(), 1);
        assert_eq!(campaigns[0].event_count, 3);
        assert!(campaigns[0].patterns.len() >= 2);
    }
}