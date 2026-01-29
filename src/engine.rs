//! Core correlation engine for attack detection.
//!
//! This engine processes security events, correlates them into campaigns,
//! calculates threat scores, and determines appropriate responses.

use crate::events::{EventId, EventSeverity, SecurityEvent};
use crate::patterns::{AttackCampaign, AttackPattern, KillChainStage, PatternDetector};
use dashmap::DashMap;
use parking_lot::RwLock;
use palisade_config::{ActionType, PolicyConfig, ResponseCondition, Severity};
use palisade_errors::{definitions, AgentError, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::Timelike;

/// Correlation engine state
pub struct CorrelationEngine {
    /// Policy configuration
    policy: Arc<RwLock<PolicyConfig>>,
    
    /// Pattern detector
    pattern_detector: Arc<RwLock<PatternDetector>>,
    
    /// Active campaigns by source IP
    campaigns: Arc<DashMap<String, AttackCampaign>>,
    
    /// Event counter for generating IDs
    event_counter: Arc<AtomicU64>,
    
    /// Incident counter
    incident_counter: Arc<AtomicU64>,
    
    /// Last response time by campaign ID (for cooldown)
    last_response_time: Arc<DashMap<String, u64>>,
}

/// Correlation result
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    /// Calculated threat score
    pub score: f64,
    
    /// Event severity
    pub severity: EventSeverity,
    
    /// Detected attack patterns
    pub patterns: Vec<AttackPattern>,
    
    /// Campaign ID (if part of ongoing campaign)
    pub campaign_id: Option<String>,
    
    /// Recommended action
    pub action: ActionType,
    
    /// Whether response is on cooldown
    pub on_cooldown: bool,
    
    /// Kill chain stage (if determinable)
    pub kill_chain_stage: Option<KillChainStage>,
}

/// Incident details
#[derive(Debug, Clone)]
pub struct Incident {
    /// Incident ID
    pub id: u64,
    
    /// Associated events
    pub events: Vec<EventId>,
    
    /// Source IP
    pub source_ip: String,
    
    /// Incident score
    pub score: f64,
    
    /// Severity
    pub severity: EventSeverity,
    
    /// Detected patterns
    pub patterns: Vec<AttackPattern>,
    
    /// Timestamp
    pub timestamp: u64,
    
    /// Recommended action
    pub action: ActionType,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(policy: PolicyConfig) -> Self {
        let max_events = policy.scoring.max_events_in_memory;
        
        Self {
            policy: Arc::new(RwLock::new(policy)),
            pattern_detector: Arc::new(RwLock::new(PatternDetector::new(max_events))),
            campaigns: Arc::new(DashMap::new()),
            event_counter: Arc::new(AtomicU64::new(0)),
            incident_counter: Arc::new(AtomicU64::new(0)),
            last_response_time: Arc::new(DashMap::new()),
        }
    }
    
    /// Process a security event and correlate it
    pub fn correlate(&self, mut event: SecurityEvent) -> Result<CorrelationResult> {
        // Assign event ID if not set
        if event.id == 0 {
            event.id = self.event_counter.fetch_add(1, Ordering::SeqCst);
        }
        
        let policy = self.policy.read();
        let source_ip = event.source_ip.to_string();
        
        // Calculate base score
        let mut score = self.calculate_event_score(&event, &policy);
        
        // Detect patterns
        let patterns = {
            let mut detector = self.pattern_detector.write();
            detector.analyze(&event)
        };
        
        // Update or create campaign
        let campaign_id = self.update_campaign(&source_ip, &event, &patterns, score);
        
        // Apply correlation bonus if part of campaign
        if let Some(ref cid) = campaign_id {
            if let Some(campaign) = self.campaigns.get(cid) {
                // Boost score based on campaign history
                let correlation_boost = (campaign.event_count as f64 * 2.0).min(20.0);
                score += correlation_boost;
            }
        }
        
        // Determine severity
        let severity = EventSeverity::from_score(score);
        
        // Determine action
        let action = self.determine_action(score, severity, &event, &policy)?;
        
        // Check cooldown
        let on_cooldown = self.is_on_cooldown(&campaign_id, &policy);
        
        // Infer kill chain stage
        let kill_chain_stage = PatternDetector::infer_kill_chain_stage(&patterns);
        
        Ok(CorrelationResult {
            score,
            severity,
            patterns,
            campaign_id,
            action,
            on_cooldown,
            kill_chain_stage,
        })
    }
    
    /// Calculate score for a single event
    fn calculate_event_score(&self, event: &SecurityEvent, policy: &PolicyConfig) -> f64 {
        use crate::events::EventType;
        
        let weights = &policy.scoring.weights;
        let mut score = 0.0;
        
        // Base score from event type
        match &event.event_type {
            EventType::ArtifactAccess { .. } => {
                score += weights.artifact_access;
            }
            EventType::SuspiciousProcess { .. } => {
                score += weights.suspicious_process;
            }
            EventType::RapidEnumeration { .. } => {
                score += weights.rapid_enumeration;
            }
            EventType::OffHoursActivity { .. } => {
                if policy.scoring.enable_time_scoring {
                    score += weights.off_hours_activity;
                }
            }
            EventType::SuspiciousAncestry { .. } => {
                if policy.scoring.enable_ancestry_tracking {
                    score += weights.ancestry_suspicious;
                }
            }
            EventType::AuthenticationFailure { .. } => {
                score += 15.0;
            }
            EventType::PathTraversal { .. } => {
                score += 25.0;
            }
            EventType::SqlInjection { .. } => {
                score += 30.0;
            }
            EventType::CommandInjection { .. } => {
                score += 35.0;
            }
            EventType::ConfigurationChange { .. } => {
                score += 10.0;
            }
            EventType::ErrorEvent { .. } => {
                score += 5.0;
            }
        }
        
        // Apply confidence modifier
        score *= event.confidence / 100.0;
        
        score
    }
    
    /// Update or create attack campaign
    fn update_campaign(
        &self,
        source_ip: &str,
        event: &SecurityEvent,
        patterns: &[AttackPattern],
        _score: f64,
    ) -> Option<String> {
        let campaign_id = format!("campaign-{}", source_ip);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.campaigns
            .entry(campaign_id.clone())
            .and_modify(|campaign| {
                campaign.last_activity = now;
                campaign.event_count += 1;
                
                // Merge patterns (avoid duplicates)
                for pattern in patterns {
                    if !campaign.patterns.contains(pattern) {
                        campaign.patterns.push(pattern.clone());
                    }
                }
                
                // Update confidence (running average)
                campaign.confidence = 
                    (campaign.confidence * 0.8) + (event.confidence * 0.2);
                
                // Update kill chain stage
                campaign.kill_chain_stage = 
                    PatternDetector::infer_kill_chain_stage(&campaign.patterns);
            })
            .or_insert_with(|| AttackCampaign {
                id: campaign_id.clone(),
                source_ip: source_ip.to_string(),
                start_time: now,
                last_activity: now,
                patterns: patterns.to_vec(),
                event_count: 1,
                confidence: event.confidence,
                kill_chain_stage: PatternDetector::infer_kill_chain_stage(patterns),
            });
        
        Some(campaign_id)
    }
    
    /// Determine appropriate action based on score and policy
    fn determine_action(
        &self,
        _score: f64,
        severity: EventSeverity,
        event: &SecurityEvent,
        policy: &PolicyConfig,
    ) -> Result<ActionType> {
        // Convert our EventSeverity to palisade_config::Severity
        let policy_severity = match severity {
            EventSeverity::Low => Severity::Low,
            EventSeverity::Medium => Severity::Medium,
            EventSeverity::High => Severity::High,
            EventSeverity::Critical => Severity::Critical,
        };
        
        // Find matching response rule
        for rule in &policy.response.rules {
            if rule.severity != policy_severity {
                continue;
            }
            
            // Check all conditions
            let mut conditions_met = true;
            
            for condition in &rule.conditions {
                match condition {
                    ResponseCondition::MinConfidence { threshold } => {
                        if event.confidence < *threshold {
                            conditions_met = false;
                            break;
                        }
                    }
                    ResponseCondition::TimeWindow { start_hour, end_hour } => {
                        let current_hour = chrono::Utc::now().hour() as u8;
                        if current_hour < *start_hour || current_hour >= *end_hour {
                            conditions_met = false;
                            break;
                        }
                    }
                    ResponseCondition::NotParentedBy { .. } => {
                        // Process ancestry checking not implemented - skip condition
                        // In production, would check if event's process is NOT parented by specified process
                    }
                    ResponseCondition::MinSignalTypes { count } => {
                        // Check if minimum number of different signal types seen
                        // For now, assume condition is met (requires campaign context)
                        if *count > 1 {
                            // This would require checking campaign history for signal type diversity
                            // Simplified implementation - always pass for now
                        }
                    }
                    ResponseCondition::RepeatCount { count, .. } => {
                        // Check if event has repeated N times within window
                        // For now, assume condition is met (requires campaign context)
                        if *count > 1 {
                            // This would require checking campaign history for repeat events
                            // Simplified implementation - always pass for now
                        }
                    }
                    ResponseCondition::Custom { name, .. } => {
                        // Custom conditions would be evaluated by external handler
                        // For now, we validate that they're registered
                        if !policy.registered_custom_conditions.contains(name) {
                            return Err(AgentError::response(
                                definitions::RSP_EXEC_FAILED,
                                "determine_action",
                                format!("Unregistered custom condition: {}", name)
                            ));
                        }
                    }
                }
            }
            
            if conditions_met {
                return Ok(rule.action.clone());
            }
        }
        
        // Default action if no rule matches
        Ok(ActionType::Log)
    }
    
    /// Check if response is on cooldown
    fn is_on_cooldown(&self, campaign_id: &Option<String>, policy: &PolicyConfig) -> bool {
        if let Some(cid) = campaign_id {
            if let Some(last_response) = self.last_response_time.get(cid) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                let elapsed = now - *last_response;
                return elapsed < policy.response.cooldown_secs;
            }
        }
        
        false
    }
    
    /// Record response action
    pub fn record_response(&self, campaign_id: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.last_response_time.insert(campaign_id.to_string(), now);
    }
    
    /// Get active campaigns
    pub fn get_active_campaigns(&self) -> Vec<AttackCampaign> {
        self.campaigns
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
    
    /// Get campaign by ID
    pub fn get_campaign(&self, campaign_id: &str) -> Option<AttackCampaign> {
        self.campaigns.get(campaign_id).map(|c| c.clone())
    }
    
    /// Prune stale campaigns (inactive for X seconds)
    pub fn prune_stale_campaigns(&self, max_age_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.campaigns.retain(|_, campaign| {
            (now - campaign.last_activity) < max_age_secs
        });
    }
    
    /// Hot-reload policy
    pub fn reload_policy(&self, new_policy: PolicyConfig) -> Result<()> {
        // Validate new policy
        new_policy.validate()?;
        
        // Apply new policy
        let mut policy = self.policy.write();
        *policy = new_policy;
        
        Ok(())
    }
    
    /// Get current policy (for inspection)
    pub fn get_policy(&self) -> PolicyConfig {
        self.policy.read().clone()
    }
    
    /// Create incident from correlation result
    pub fn create_incident(
        &self,
        event_ids: Vec<EventId>,
        source_ip: String,
        result: &CorrelationResult,
    ) -> Incident {
        let incident_id = self.incident_counter.fetch_add(1, Ordering::SeqCst);
        
        Incident {
            id: incident_id,
            events: event_ids,
            source_ip,
            score: result.score,
            severity: result.severity,
            patterns: result.patterns.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            action: result.action.clone(),
        }
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> EngineStats {
        EngineStats {
            total_events_processed: self.event_counter.load(Ordering::SeqCst),
            total_incidents: self.incident_counter.load(Ordering::SeqCst),
            active_campaigns: self.campaigns.len(),
            tracked_ips: {
                let detector = self.pattern_detector.read();
                detector.tracked_ip_count()
            },
        }
    }
}

/// Engine statistics
#[derive(Debug, Clone)]
pub struct EngineStats {
    pub total_events_processed: u64,
    pub total_incidents: u64,
    pub active_campaigns: usize,
    pub tracked_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventType;
    use std::net::IpAddr;
    
    #[test]
    fn test_engine_creation() {
        let policy = PolicyConfig::default();
        let engine = CorrelationEngine::new(policy);
        
        let stats = engine.get_stats();
        assert_eq!(stats.total_events_processed, 0);
        assert_eq!(stats.active_campaigns, 0);
    }
    
    #[test]
    fn test_event_correlation() {
        let policy = PolicyConfig::default();
        let engine = CorrelationEngine::new(policy);
        
        let event = SecurityEvent::new(
            0,
            "192.168.1.100".parse::<IpAddr>().unwrap(),
            "session-1".to_string(),
            EventType::ArtifactAccess {
                artifact_id: "fake-aws-creds".to_string(),
                artifact_tag: "tag-123".to_string(),
            },
        )
        .with_confidence(80.0);
        
        let result = engine.correlate(event).unwrap();
        
        assert!(result.score > 0.0);
        assert!(result.patterns.contains(&AttackPattern::CredentialAccess));
        assert!(result.campaign_id.is_some());
    }
    
    #[test]
    fn test_campaign_tracking() {
        let policy = PolicyConfig::default();
        let engine = CorrelationEngine::new(policy);
        
        // Simulate 3 events from same IP
        for i in 0..3 {
            let event = SecurityEvent::new(
                0,
                "192.168.1.100".parse::<IpAddr>().unwrap(),
                format!("session-{}", i),
                EventType::AuthenticationFailure {
                    username: "admin".to_string(),
                    method: "password".to_string(),
                },
            );
            
            let _ = engine.correlate(event);
        }
        
        let campaigns = engine.get_active_campaigns();
        assert_eq!(campaigns.len(), 1);
        assert_eq!(campaigns[0].event_count, 3);
    }
}