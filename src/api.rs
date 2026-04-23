//! Public operational API for hardened correlation workflows.

use crate::engine::{
    ACTION_ALERT, ACTION_CUSTOM_SCRIPT, ACTION_ISOLATE_HOST, ACTION_KILL_PROCESS, ACTION_LOG,
    CorrelationEngine, MAX_ACTION_PATH_LEN, MAX_HISTORY_DEPTH, MAX_IP_TEXT_LEN,
    MAX_TRACKED_SOURCES, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_INFORMATIONAL, SEVERITY_LOW,
    SEVERITY_MEDIUM,
};
use crate::error_codes::COR_CONTEXT_LOAD_FAILED;
#[cfg(feature = "log")]
use crate::error_codes::{COR_DATA_INGEST_FAILED, COR_RULE_UPDATE_FAILED, LOG_FILE_WRITE_FAILED};
use crate::events::{EventContext, EventKind};
use crate::patterns::{
    KILL_CHAIN_ACTIONS_ON_OBJECTIVES, KILL_CHAIN_COMMAND_AND_CONTROL, KILL_CHAIN_DELIVERY,
    KILL_CHAIN_EXPLOITATION, KILL_CHAIN_INSTALLATION, KILL_CHAIN_NONE, KILL_CHAIN_RECONNAISSANCE,
    KILL_CHAIN_WEAPONIZATION, MAX_PATTERNS_PER_RESULT, PATTERN_BRUTE_FORCE,
    PATTERN_COMMAND_AND_CONTROL, PATTERN_CREDENTIAL_ACCESS, PATTERN_CREDENTIAL_DUMPING,
    PATTERN_DENIAL_OF_SERVICE, PATTERN_DISCOVERY, PATTERN_EXECUTION, PATTERN_EXPLOITATION,
    PATTERN_HONEYPOT_PROBING, PATTERN_LATERAL_MOVEMENT, PATTERN_PROCESS_DISCOVERY,
};
use crate::timing::enforce_timing_floor;
#[cfg(feature = "log")]
use core::fmt::Write as _;
#[cfg(feature = "log")]
use heapless::String as HString;
use palisade_config::{DEFAULT_TIMING_FLOOR as PALISADE_DEFAULT_TIMING_FLOOR, PolicyConfig};
use palisade_errors::AgentError;
use parking_lot::RwLock;
#[cfg(feature = "log")]
use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(feature = "log")]
const COR_OBSERVE_EVENT: u16 = COR_DATA_INGEST_FAILED;
#[cfg(feature = "log")]
const COR_POLICY_EVENT: u16 = COR_RULE_UPDATE_FAILED;
#[cfg(feature = "log")]
const COR_RESPONSE_EVENT: u16 = COR_CONTEXT_LOAD_FAILED;
#[cfg(feature = "log")]
const AUDIT_INTERNAL_CAP: usize = 256;
#[cfg(feature = "log")]
const AUDIT_SENSITIVE_CAP: usize = 512;

/// Hardened operational API for correlation workflows.
///
/// This is the only public type exported by the crate. Event ingestion,
/// correlation state maintenance, policy reloads, result inspection, and
/// optional encrypted audit logging all go through its inherent methods.
pub struct CorrelationApi<'a> {
    engine: Box<RwLock<CorrelationEngine>>,
    timing_floor: Option<Duration>,
    marker: PhantomData<&'a Path>,
    #[cfg(feature = "log")]
    logging: CorrelationLogging<'a>,
}

#[cfg(feature = "log")]
enum SuccessAudit {
    Observation {
        action: &'static str,
        source_ip: IpAddr,
    },
    PolicyUpdate {
        action: &'static str,
        max_events_in_memory: usize,
        cooldown_secs: u64,
    },
    ResponseControl {
        action: &'static str,
        source_ip: Option<IpAddr>,
        value: u64,
    },
}

const ENGINE_INIT_STACK_SIZE: usize = 4 * 1024 * 1024;

impl<'a> CorrelationApi<'a> {
    /// Default minimum duration applied to production API operations.
    pub const DEFAULT_TIMING_FLOOR: Duration = PALISADE_DEFAULT_TIMING_FLOOR;

    /// Maximum number of tracked sources retained by the fixed-capacity engine.
    pub const MAX_TRACKED_SOURCES: usize = MAX_TRACKED_SOURCES;

    /// Maximum number of pattern codes exposed for the last result.
    pub const MAX_PATTERN_CODES: usize = MAX_PATTERNS_PER_RESULT;

    /// Maximum bytes required to format the last source IP as UTF-8 text.
    pub const MAX_SOURCE_IP_TEXT_LEN: usize = MAX_IP_TEXT_LEN;

    /// Maximum bytes retained for a custom-script action path.
    pub const MAX_ACTION_SCRIPT_PATH_LEN: usize = MAX_ACTION_PATH_LEN;

    /// Maximum events that a compatible no-allocation policy may retain per source.
    pub const MAX_EVENTS_PER_SOURCE: usize = MAX_HISTORY_DEPTH;

    /// Informational severity code.
    pub const SEVERITY_INFORMATIONAL: u8 = SEVERITY_INFORMATIONAL;

    /// Low severity code.
    pub const SEVERITY_LOW: u8 = SEVERITY_LOW;

    /// Medium severity code.
    pub const SEVERITY_MEDIUM: u8 = SEVERITY_MEDIUM;

    /// High severity code.
    pub const SEVERITY_HIGH: u8 = SEVERITY_HIGH;

    /// Critical severity code.
    pub const SEVERITY_CRITICAL: u8 = SEVERITY_CRITICAL;

    /// Log-only action code.
    pub const ACTION_LOG: u8 = ACTION_LOG;

    /// Alert action code.
    pub const ACTION_ALERT: u8 = ACTION_ALERT;

    /// Kill-process action code.
    pub const ACTION_KILL_PROCESS: u8 = ACTION_KILL_PROCESS;

    /// Isolate-host action code.
    pub const ACTION_ISOLATE_HOST: u8 = ACTION_ISOLATE_HOST;

    /// Custom-script action code.
    pub const ACTION_CUSTOM_SCRIPT: u8 = ACTION_CUSTOM_SCRIPT;

    /// No kill-chain stage available.
    pub const KILL_CHAIN_NONE: u8 = KILL_CHAIN_NONE;

    /// Reconnaissance kill-chain stage code.
    pub const KILL_CHAIN_RECONNAISSANCE: u8 = KILL_CHAIN_RECONNAISSANCE;

    /// Weaponization kill-chain stage code.
    pub const KILL_CHAIN_WEAPONIZATION: u8 = KILL_CHAIN_WEAPONIZATION;

    /// Delivery kill-chain stage code.
    pub const KILL_CHAIN_DELIVERY: u8 = KILL_CHAIN_DELIVERY;

    /// Exploitation kill-chain stage code.
    pub const KILL_CHAIN_EXPLOITATION: u8 = KILL_CHAIN_EXPLOITATION;

    /// Installation kill-chain stage code.
    pub const KILL_CHAIN_INSTALLATION: u8 = KILL_CHAIN_INSTALLATION;

    /// Command-and-control kill-chain stage code.
    pub const KILL_CHAIN_COMMAND_AND_CONTROL: u8 = KILL_CHAIN_COMMAND_AND_CONTROL;

    /// Actions-on-objectives kill-chain stage code.
    pub const KILL_CHAIN_ACTIONS_ON_OBJECTIVES: u8 = KILL_CHAIN_ACTIONS_ON_OBJECTIVES;

    /// Brute-force pattern code.
    pub const PATTERN_BRUTE_FORCE: u16 = PATTERN_BRUTE_FORCE;

    /// Discovery pattern code.
    pub const PATTERN_DISCOVERY: u16 = PATTERN_DISCOVERY;

    /// Credential-access pattern code.
    pub const PATTERN_CREDENTIAL_ACCESS: u16 = PATTERN_CREDENTIAL_ACCESS;

    /// Exploitation pattern code.
    pub const PATTERN_EXPLOITATION: u16 = PATTERN_EXPLOITATION;

    /// Lateral-movement pattern code.
    pub const PATTERN_LATERAL_MOVEMENT: u16 = PATTERN_LATERAL_MOVEMENT;

    /// Denial-of-service pattern code.
    pub const PATTERN_DENIAL_OF_SERVICE: u16 = PATTERN_DENIAL_OF_SERVICE;

    /// Command-and-control pattern code.
    pub const PATTERN_COMMAND_AND_CONTROL: u16 = PATTERN_COMMAND_AND_CONTROL;

    /// Credential-dumping pattern code.
    pub const PATTERN_CREDENTIAL_DUMPING: u16 = PATTERN_CREDENTIAL_DUMPING;

    /// Execution pattern code.
    pub const PATTERN_EXECUTION: u16 = PATTERN_EXECUTION;

    /// Process-discovery pattern code.
    pub const PATTERN_PROCESS_DISCOVERY: u16 = PATTERN_PROCESS_DISCOVERY;

    /// Honeypot-probing pattern code.
    pub const PATTERN_HONEYPOT_PROBING: u16 = PATTERN_HONEYPOT_PROBING;

    /// Create a correlation API from a validated `palisade-config` policy.
    ///
    /// In the Palisade ecosystem, the intended flow is:
    ///
    /// 1. load or validate `PolicyConfig` through `palisade_config::PolicyApi`
    /// 2. construct `CorrelationApi`
    /// 3. handle any failure through `palisade_errors::AgentError`
    pub fn new(policy: &PolicyConfig) -> Result<Self, AgentError> {
        let engine = thread::scope(|scope| {
            thread::Builder::new()
                .stack_size(ENGINE_INIT_STACK_SIZE)
                .spawn_scoped(scope, || CorrelationEngine::from_policy(policy))
                .map_err(|_| {
                    AgentError::new(
                        COR_CONTEXT_LOAD_FAILED,
                        "Correlation engine initialization failed",
                        "operation=spawn_engine_init_thread; unable to reserve hardened initialization stack",
                        "engine.init",
                    )
                })?
                .join()
                .map_err(|_| {
                    AgentError::new(
                        COR_CONTEXT_LOAD_FAILED,
                        "Correlation engine initialization failed",
                        "operation=join_engine_init_thread; initialization thread panicked",
                        "engine.init",
                    )
                })?
        })?;

        Ok(Self {
            engine: Box::new(RwLock::new(engine)),
            timing_floor: None,
            marker: PhantomData,
            #[cfg(feature = "log")]
            logging: CorrelationLogging::default(),
        })
    }

    /// Prepare a policy for the hardened fixed-capacity runtime used by this crate.
    ///
    /// This method is intended for production flows that start from
    /// `PolicyConfig::default()` or other policies validated by
    /// `palisade-config`. It performs one explicit normalization:
    ///
    /// - `scoring.max_events_in_memory` is capped at `MAX_EVENTS_PER_SOURCE`
    ///
    /// Other unsupported policy shapes still fail closed.
    pub fn harden_policy(policy: &mut PolicyConfig) -> Result<(), AgentError> {
        if policy.scoring.max_events_in_memory > Self::MAX_EVENTS_PER_SOURCE {
            policy.scoring.max_events_in_memory = Self::MAX_EVENTS_PER_SOURCE;
        }

        let _ = CorrelationEngine::from_policy(policy)?;
        Ok(())
    }

    /// Create a production-ready correlation API from a mutable policy.
    ///
    /// This path is intended to compose directly with the defaults and loaders
    /// provided by `palisade-config`. It applies `harden_policy(...)` and then
    /// enables the Palisade default timing floor.
    pub fn new_production(policy: &mut PolicyConfig) -> Result<Self, AgentError> {
        Self::harden_policy(policy)?;
        Self::new(policy).map(|api| api.with_timing_floor(Self::DEFAULT_TIMING_FLOOR))
    }

    /// Apply a minimum total duration to this API's public operations.
    #[must_use]
    pub fn with_timing_floor(mut self, floor: Duration) -> Self {
        self.timing_floor = Some(floor);
        self
    }

    /// Enable hardened encrypted audit persistence to `path`.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn with_log_path(mut self, path: &'a Path) -> Self {
        self.logging.path = Some(path);
        self.logging.log_errors = true;
        self
    }

    /// Configure whether operation errors are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_errors(mut self, enabled: bool) -> Self {
        self.logging.log_errors = enabled;
        self
    }

    /// Configure whether successful observation actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_observations(mut self, enabled: bool) -> Self {
        self.logging.log_observations = enabled;
        self
    }

    /// Configure whether successful policy update actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_policy_updates(mut self, enabled: bool) -> Self {
        self.logging.log_policy_updates = enabled;
        self
    }

    /// Configure whether successful response-bookkeeping actions are persisted.
    #[cfg(feature = "log")]
    #[cfg_attr(docsrs, doc(cfg(feature = "log")))]
    #[must_use]
    pub fn log_response_actions(mut self, enabled: bool) -> Self {
        self.logging.log_response_actions = enabled;
        self
    }

    /// Reload the runtime policy used by the correlation engine.
    pub fn reload_policy(&self, policy: &PolicyConfig) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.engine.write().reload_policy(policy);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::PolicyUpdate {
                action: "correlation.reload_policy.success",
                max_events_in_memory: policy.scoring.max_events_in_memory,
                cooldown_secs: policy.response.cooldown_secs,
            }),
        )
    }

    /// Prepare and reload a policy for production use.
    ///
    /// This method applies the same explicit normalization and timing-floor
    /// posture as `new_production(...)`.
    pub fn reload_policy_production(&self, policy: &mut PolicyConfig) -> Result<(), AgentError> {
        Self::harden_policy(policy)?;
        self.reload_policy(policy)
    }

    /// Check whether a process name matches the loaded suspicious-process policy.
    pub fn is_suspicious_process(&self, process_name: &str) -> bool {
        self.engine.read().is_suspicious_process(process_name)
    }

    /// Record that a response was executed for the given source IP.
    pub fn record_response_for_source(&self, source_ip: IpAddr) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.engine.write().record_response_for_source(source_ip);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::ResponseControl {
                action: "correlation.record_response.success",
                source_ip: Some(source_ip),
                value: 0,
            }),
        )
    }

    /// Drop sources that have been inactive for at least `max_age_secs`.
    pub fn prune_stale_sources(&self, max_age_secs: u64) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.engine.write().prune_stale_sources(max_age_secs);
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::ResponseControl {
                action: "correlation.prune_stale_sources.success",
                source_ip: None,
                value: max_age_secs,
            }),
        )
    }

    /// Observe access to a deception artifact.
    pub fn observe_artifact_access(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        artifact_id: &str,
        artifact_tag: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::ArtifactAccess {
                artifact_id,
                artifact_tag,
            },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_artifact_access",
                source_ip,
            }),
        )
    }

    /// Observe a suspicious process execution signal.
    pub fn observe_suspicious_process(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        process_name: &str,
        pid: u32,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::SuspiciousProcess { process_name, pid },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_suspicious_process",
                source_ip,
            }),
        )
    }

    /// Observe rapid enumeration activity.
    pub fn observe_rapid_enumeration(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        target_count: usize,
        time_window_secs: u64,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::RapidEnumeration {
                target_count,
                time_window_secs,
            },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_rapid_enumeration",
                source_ip,
            }),
        )
    }

    /// Observe off-hours activity.
    pub fn observe_off_hours_activity(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        hour: u8,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::OffHoursActivity { hour },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_off_hours_activity",
                source_ip,
            }),
        )
    }

    /// Observe suspicious process ancestry.
    pub fn observe_suspicious_ancestry(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        process_chain: &[&str],
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::SuspiciousAncestry { process_chain },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_suspicious_ancestry",
                source_ip,
            }),
        )
    }

    /// Observe an authentication failure.
    pub fn observe_authentication_failure(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        username: &str,
        method: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::AuthenticationFailure { username, method },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_authentication_failure",
                source_ip,
            }),
        )
    }

    /// Observe a path-traversal attempt.
    pub fn observe_path_traversal(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        attempted_path: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::PathTraversal { attempted_path },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_path_traversal",
                source_ip,
            }),
        )
    }

    /// Observe a SQL-injection attempt.
    pub fn observe_sql_injection(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        payload: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::SqlInjection { payload },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_sql_injection",
                source_ip,
            }),
        )
    }

    /// Observe a command-injection attempt.
    pub fn observe_command_injection(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        command: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::CommandInjection { command },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_command_injection",
                source_ip,
            }),
        )
    }

    /// Observe a configuration change relevant to correlation.
    pub fn observe_configuration_change(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        field: &str,
        old_value: &str,
        new_value: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::ConfigurationChange {
                field,
                old_value,
                new_value,
            },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_configuration_change",
                source_ip,
            }),
        )
    }

    /// Observe an error-derived security signal.
    pub fn observe_error(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        error_code: &str,
        operation: &str,
        category: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::ErrorEvent {
                error_code,
                operation,
                category,
            },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_error",
                source_ip,
            }),
        )
    }

    /// Observe a network probing signal.
    pub fn observe_network_probe(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        ports: &str,
        protocol: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::NetworkProbe { ports, protocol },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_network_probe",
                source_ip,
            }),
        )
    }

    /// Observe a malware-download signal.
    pub fn observe_malware_download(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        source: &str,
        hash: Option<&str>,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::MalwareDownload { source, hash },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_malware_download",
                source_ip,
            }),
        )
    }

    /// Observe command-and-control communication.
    pub fn observe_c2_communication(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        destination: &str,
        protocol: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::C2Communication {
                destination,
                protocol,
            },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_c2_communication",
                source_ip,
            }),
        )
    }

    /// Observe a user-defined custom signal identifier.
    pub fn observe_custom_signal(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        type_id: &str,
        confidence: f64,
    ) -> Result<(), AgentError> {
        let started = Instant::now();
        let result = self.observe(
            source_ip,
            session_id,
            confidence,
            EventKind::Custom { type_id },
        );
        self.finish_result(
            started,
            result,
            #[cfg(feature = "log")]
            Some(SuccessAudit::Observation {
                action: "correlation.observe_custom_signal",
                source_ip,
            }),
        )
    }

    /// Return whether the API has recorded at least one result.
    pub fn has_last_result(&self) -> bool {
        self.engine.read().has_last_result()
    }

    /// Return the last computed score.
    pub fn last_score(&self) -> f64 {
        self.engine.read().last_score()
    }

    /// Return the last severity code.
    pub fn last_severity_code(&self) -> u8 {
        self.engine.read().last_severity_code()
    }

    /// Return the last action code.
    pub fn last_action_code(&self) -> u8 {
        self.engine.read().last_action_code()
    }

    /// Return whether the last source was inside the response cooldown window.
    pub fn last_on_cooldown(&self) -> bool {
        self.engine.read().last_on_cooldown()
    }

    /// Return the last kill-chain stage code.
    pub fn last_kill_chain_stage_code(&self) -> u8 {
        self.engine.read().last_kill_chain_stage_code()
    }

    /// Return the number of pattern codes retained for the last result.
    pub fn last_pattern_count(&self) -> usize {
        self.engine.read().last_pattern_codes().len()
    }

    /// Copy the last pattern codes into `out`, returning the number written.
    pub fn write_last_pattern_codes(&self, out: &mut [u16]) -> usize {
        let patterns = self.engine.read();
        let codes = patterns.last_pattern_codes();
        let copy_len = codes.len().min(out.len());
        out[..copy_len].copy_from_slice(&codes[..copy_len]);
        copy_len
    }

    /// Copy the last custom-script path into `out`, returning the number written.
    ///
    /// Returns `0` when the last action was not `ACTION_CUSTOM_SCRIPT`.
    pub fn write_last_action_script_path(&self, out: &mut [u8]) -> usize {
        self.engine.read().write_last_action_script_path(out)
    }

    /// Copy the last source IP text into `out`, returning the number written.
    pub fn write_last_source_ip(&self, out: &mut [u8]) -> usize {
        self.engine.read().write_last_source_ip(out)
    }

    /// Return the total number of observed events processed by this API.
    pub fn total_events_processed(&self) -> u64 {
        self.engine.read().total_events_processed()
    }

    /// Return the number of sources currently tracked in the fixed-capacity engine.
    pub fn tracked_sources(&self) -> usize {
        self.engine.read().tracked_sources()
    }

    fn observe(
        &self,
        source_ip: IpAddr,
        session_id: &str,
        confidence: f64,
        kind: EventKind<'_>,
    ) -> Result<(), AgentError> {
        let event = EventContext::new(source_ip, session_id, confidence, kind)?;
        self.engine.write().process(event)
    }

    fn finish_result(
        &self,
        started: Instant,
        result: Result<(), AgentError>,
        #[cfg(feature = "log")] success_action: Option<SuccessAudit>,
    ) -> Result<(), AgentError> {
        match result {
            Ok(()) => {
                #[cfg(feature = "log")]
                if let Some(action) = success_action {
                    self.log_success_action(action)?;
                }
                self.finish_success(started);
                Ok(())
            }
            Err(error) => {
                #[cfg(feature = "log")]
                if let Err(log_failure) = self.logging.log_error(&error) {
                    return Err(self.normalize_error(log_failure, started));
                }
                Err(self.normalize_error(error, started))
            }
        }
    }

    fn normalize_error(&self, error: AgentError, started: Instant) -> AgentError {
        if let Some(floor) = self.timing_floor {
            let elapsed = started.elapsed();
            if elapsed >= floor {
                error
            } else {
                error.with_timing_normalization(floor)
            }
        } else {
            error
        }
    }

    fn finish_success(&self, started: Instant) {
        if let Some(floor) = self.timing_floor {
            enforce_timing_floor(started, floor);
        }
    }

    #[cfg(feature = "log")]
    fn log_success_action(&self, action: SuccessAudit) -> Result<(), AgentError> {
        match action {
            SuccessAudit::Observation { action, source_ip } => {
                if !self.logging.log_observations {
                    return Ok(());
                }

                let snapshot = self.engine.read();
                let mut internal = new_audit_buffer("correlation.log_observation_action")?;
                write!(
                    &mut internal,
                    "action={action}; score={:.2}; severity_code={}; action_code={}; on_cooldown={}; kill_chain_stage_code={}; pattern_count={}",
                    snapshot.last_score(),
                    snapshot.last_severity_code(),
                    snapshot.last_action_code(),
                    snapshot.last_on_cooldown(),
                    snapshot.last_kill_chain_stage_code(),
                    snapshot.last_pattern_codes().len()
                )
                .map_err(|_| audit_buffer_overflow("correlation.log_observation_action"))?;

                let sensitive =
                    source_ip_to_audit_text(source_ip, "correlation.log_observation_action")?;
                self.log_action(
                    COR_OBSERVE_EVENT,
                    "Correlation API action recorded",
                    internal.as_str(),
                    sensitive.as_str(),
                )
            }
            SuccessAudit::PolicyUpdate {
                action,
                max_events_in_memory,
                cooldown_secs,
            } => {
                if !self.logging.log_policy_updates {
                    return Ok(());
                }

                let mut internal = new_audit_buffer("correlation.log_policy_action")?;
                write!(
                    &mut internal,
                    "action={action}; max_events_in_memory={max_events_in_memory}; cooldown_secs={cooldown_secs}"
                )
                .map_err(|_| audit_buffer_overflow("correlation.log_policy_action"))?;
                self.log_action(
                    COR_POLICY_EVENT,
                    "Correlation API action recorded",
                    internal.as_str(),
                    "<policy>",
                )
            }
            SuccessAudit::ResponseControl {
                action,
                source_ip,
                value,
            } => {
                if !self.logging.log_response_actions {
                    return Ok(());
                }

                let mut internal = new_audit_buffer("correlation.log_response_action")?;
                if let Some(source_ip) = source_ip {
                    write!(&mut internal, "action={action}; source_ip={source_ip}")
                        .map_err(|_| audit_buffer_overflow("correlation.log_response_action"))?;
                } else {
                    write!(&mut internal, "action={action}; value={value}")
                        .map_err(|_| audit_buffer_overflow("correlation.log_response_action"))?;
                }

                let sensitive = if let Some(source_ip) = source_ip {
                    source_ip_to_audit_text(source_ip, "correlation.log_response_action")?
                } else {
                    static_audit_text("<source-table>", "correlation.log_response_action")?
                };
                self.log_action(
                    COR_RESPONSE_EVENT,
                    "Correlation API action recorded",
                    internal.as_str(),
                    sensitive.as_str(),
                )
            }
        }
    }

    #[cfg(feature = "log")]
    fn log_action(
        &self,
        code: u16,
        external: &str,
        internal: &str,
        sensitive: &str,
    ) -> Result<(), AgentError> {
        self.logging.log_record(code, external, internal, sensitive)
    }
}

#[cfg(feature = "log")]
fn log_write_failure(context: &str, path: &Path, error: &io::Error) -> AgentError {
    let mut internal = HString::<AUDIT_INTERNAL_CAP>::new();
    let _ = write!(
        &mut internal,
        "operation={context}; io_kind={}; encrypted audit persistence failed",
        error.kind()
    );
    let sensitive = path_to_audit_text(path, context).unwrap_or_else(|_| {
        let mut fallback = HString::<AUDIT_SENSITIVE_CAP>::new();
        let _ = fallback.push_str("<audit-path-overflow>");
        fallback
    });
    AgentError::new(
        LOG_FILE_WRITE_FAILED,
        "Audit operation failed",
        internal,
        sensitive,
    )
}

#[cfg(feature = "log")]
#[derive(Debug, Default)]
struct CorrelationLogging<'a> {
    path: Option<&'a Path>,
    log_errors: bool,
    log_observations: bool,
    log_policy_updates: bool,
    log_response_actions: bool,
}

#[cfg(feature = "log")]
impl<'a> CorrelationLogging<'a> {
    fn log_error(&self, error: &AgentError) -> Result<(), AgentError> {
        if self.log_errors
            && let Some(path) = self.path
        {
            error.log(path).map_err(|log_error| {
                log_write_failure("correlation.log_error", path, &log_error)
            })?;
        }

        Ok(())
    }

    fn log_record(
        &self,
        code: u16,
        external: &str,
        internal: &str,
        sensitive: &str,
    ) -> Result<(), AgentError> {
        if let Some(path) = self.path {
            let record = AgentError::new(code, external, internal, sensitive);
            record.log(path).map_err(|log_error| {
                log_write_failure("correlation.log_record", path, &log_error)
            })?;
        }

        Ok(())
    }
}

#[cfg(feature = "log")]
fn new_audit_buffer(context: &str) -> Result<HString<AUDIT_INTERNAL_CAP>, AgentError> {
    let _ = context;
    Ok(HString::new())
}

#[cfg(feature = "log")]
fn audit_buffer_overflow(context: &str) -> AgentError {
    let mut internal = HString::<AUDIT_INTERNAL_CAP>::new();
    let _ = write!(
        &mut internal,
        "operation={context}; fixed-capacity audit buffer overflow"
    );
    AgentError::new(
        LOG_FILE_WRITE_FAILED,
        "Audit operation failed",
        internal,
        context,
    )
}

#[cfg(feature = "log")]
fn path_to_audit_text(
    path: &Path,
    context: &str,
) -> Result<HString<AUDIT_SENSITIVE_CAP>, AgentError> {
    let mut sensitive = HString::<AUDIT_SENSITIVE_CAP>::new();
    write!(&mut sensitive, "{}", path.display()).map_err(|_| audit_buffer_overflow(context))?;
    Ok(sensitive)
}

#[cfg(feature = "log")]
fn source_ip_to_audit_text(
    source_ip: IpAddr,
    context: &str,
) -> Result<HString<AUDIT_SENSITIVE_CAP>, AgentError> {
    let mut sensitive = HString::<AUDIT_SENSITIVE_CAP>::new();
    write!(&mut sensitive, "{source_ip}").map_err(|_| audit_buffer_overflow(context))?;
    Ok(sensitive)
}

#[cfg(feature = "log")]
fn static_audit_text(
    value: &str,
    context: &str,
) -> Result<HString<AUDIT_SENSITIVE_CAP>, AgentError> {
    let mut sensitive = HString::<AUDIT_SENSITIVE_CAP>::new();
    sensitive
        .push_str(value)
        .map_err(|_| audit_buffer_overflow(context))?;
    Ok(sensitive)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "log")]
    use std::path::Path;

    const TEST_STACK_SIZE: usize = 8 * 1024 * 1024;

    fn hardened_policy() -> PolicyConfig {
        let mut policy = PolicyConfig::default();
        policy.scoring.max_events_in_memory = CorrelationApi::MAX_EVENTS_PER_SOURCE;
        policy
    }

    fn run_with_large_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(TEST_STACK_SIZE)
            .spawn(test)
            .expect("test thread should spawn")
            .join()
            .expect("test thread should complete");
    }

    fn make_api() -> CorrelationApi<'static> {
        CorrelationApi::new(&hardened_policy()).unwrap()
    }

    #[test]
    fn test_rejects_default_policy_shape() {
        run_with_large_stack(|| {
            assert!(CorrelationApi::new(&PolicyConfig::default()).is_err());
        });
    }

    #[test]
    fn test_full_pipeline() {
        run_with_large_stack(|| {
            let api = make_api();
            let source_ip: IpAddr = "192.168.1.100".parse().unwrap();

            api.observe_rapid_enumeration(source_ip, "session-1", 50, 30, 70.0)
                .unwrap();
            assert!(api.last_score() > 0.0);

            api.observe_artifact_access(
                source_ip,
                "session-1",
                "fake-aws-credentials",
                "tag-abc",
                100.0,
            )
            .unwrap();
            assert_eq!(api.last_action_code(), CorrelationApi::ACTION_ALERT);

            api.observe_suspicious_process(source_ip, "session-1", "mimikatz.exe", 1234, 95.0)
                .unwrap();

            let mut patterns = [0u16; CorrelationApi::MAX_PATTERN_CODES];
            let written = api.write_last_pattern_codes(&mut patterns);
            assert!(written > 0);
            assert!(patterns[..written].contains(&CorrelationApi::PATTERN_CREDENTIAL_DUMPING));
        });
    }

    #[test]
    fn test_cooldown_round_trip() {
        run_with_large_stack(|| {
            let api = make_api();
            let source_ip: IpAddr = "10.0.0.5".parse().unwrap();

            api.observe_artifact_access(source_ip, "session-1", "fake-cred", "tag-1", 90.0)
                .unwrap();
            assert!(!api.last_on_cooldown());

            api.record_response_for_source(source_ip).unwrap();
            api.observe_artifact_access(source_ip, "session-2", "fake-cred", "tag-2", 90.0)
                .unwrap();
            assert!(api.last_on_cooldown());
            assert_eq!(api.last_action_code(), CorrelationApi::ACTION_LOG);
        });
    }

    #[test]
    fn test_last_source_buffer() {
        run_with_large_stack(|| {
            let api = make_api();
            let source_ip: IpAddr = "10.0.0.6".parse().unwrap();

            api.observe_network_probe(source_ip, "session-1", "22,80,443", "TCP", 60.0)
                .unwrap();

            let mut out = [0u8; CorrelationApi::MAX_SOURCE_IP_TEXT_LEN];
            let written = api.write_last_source_ip(&mut out);
            let text = std::str::from_utf8(&out[..written]).unwrap();
            assert_eq!(text, "10.0.0.6");
        });
    }

    #[test]
    fn test_record_response_rejects_untracked_source() {
        run_with_large_stack(|| {
            let api = make_api();
            let source_ip: IpAddr = "10.0.0.200".parse().unwrap();

            assert!(api.record_response_for_source(source_ip).is_err());
        });
    }

    #[test]
    fn test_prune_rejects_zero_age() {
        run_with_large_stack(|| {
            let api = make_api();

            assert!(api.prune_stale_sources(0).is_err());
        });
    }

    #[test]
    fn test_policy_api_validated_policy_is_accepted() {
        run_with_large_stack(|| {
            let mut policy = PolicyConfig::default();
            policy.scoring.max_events_in_memory = CorrelationApi::MAX_EVENTS_PER_SOURCE;

            palisade_config::PolicyApi::new()
                .validate(&policy)
                .expect("policy should validate through palisade-config");

            let api = CorrelationApi::new(&policy).expect("validated policy should construct api");
            assert!(!api.is_suspicious_process("notepad.exe"));
        });
    }

    #[test]
    fn test_new_production_accepts_upstream_default_policy() {
        run_with_large_stack(|| {
            let mut policy = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut policy)
                .expect("production path should harden defaults");

            assert_eq!(
                policy.scoring.max_events_in_memory,
                CorrelationApi::MAX_EVENTS_PER_SOURCE
            );
            assert!(api.is_suspicious_process("MIMIKATZ.exe"));
        });
    }

    #[test]
    fn test_reload_policy_production_hardens_default_policy() {
        run_with_large_stack(|| {
            let mut initial = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut initial)
                .expect("production path should construct from defaults");

            let mut reload = PolicyConfig::default();
            api.reload_policy_production(&mut reload)
                .expect("production reload should harden defaults");

            assert_eq!(
                reload.scoring.max_events_in_memory,
                CorrelationApi::MAX_EVENTS_PER_SOURCE
            );
        });
    }

    #[test]
    fn test_harden_policy_still_rejects_unsupported_custom_conditions() {
        run_with_large_stack(|| {
            let mut policy = PolicyConfig::default();
            policy
                .registered_custom_conditions
                .insert("geo_allowlist".into());
            policy.response.rules[0]
                .conditions
                .push(palisade_config::ResponseCondition::Custom {
                    name: "geo_allowlist".into(),
                    params: std::collections::HashMap::new(),
                });

            assert!(CorrelationApi::harden_policy(&mut policy).is_err());
        });
    }

    #[cfg(feature = "log")]
    #[test]
    fn correlation_api_can_log_observations() {
        run_with_large_stack(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let log_path = dir.path().join("correlation-observations.log");
            let mut policy = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut policy)
                .expect("production api")
                .with_log_path(&log_path)
                .log_observations(true);

            api.observe_artifact_access(
                "192.168.1.100".parse().expect("ip"),
                "session-1",
                "fake-aws-credentials",
                "aws-prod-decoy",
                100.0,
            )
            .expect("observation should succeed");

            assert!(log_path.exists());
        });
    }

    #[cfg(feature = "log")]
    #[test]
    fn correlation_api_can_log_errors() {
        run_with_large_stack(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let log_path = dir.path().join("correlation-errors.log");
            let mut policy = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut policy)
                .expect("production api")
                .with_log_path(&log_path)
                .log_errors(true);

            let _ = api.observe_artifact_access(
                "192.168.1.100".parse().expect("ip"),
                "",
                "fake-aws-credentials",
                "aws-prod-decoy",
                100.0,
            );

            assert!(log_path.exists());
        });
    }

    #[cfg(feature = "log")]
    #[test]
    fn correlation_api_fails_closed_when_observation_logging_cannot_persist() {
        run_with_large_stack(|| {
            let mut policy = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut policy)
                .expect("production api")
                .with_log_path(Path::new("relative-correlation-audit.log"))
                .log_observations(true);

            let err = api
                .observe_artifact_access(
                    "192.168.1.100".parse().expect("ip"),
                    "session-1",
                    "fake-aws-credentials",
                    "aws-prod-decoy",
                    100.0,
                )
                .expect_err("relative log path should fail closed");

            assert_eq!(err.to_string(), "Audit operation failed");
        });
    }

    #[cfg(feature = "log")]
    #[test]
    fn correlation_api_fails_closed_when_error_logging_cannot_persist() {
        run_with_large_stack(|| {
            let mut policy = PolicyConfig::default();
            let api = CorrelationApi::new_production(&mut policy)
                .expect("production api")
                .with_log_path(Path::new("relative-correlation-errors.log"))
                .log_errors(true);

            let err = api
                .observe_artifact_access(
                    "192.168.1.100".parse().expect("ip"),
                    "",
                    "fake-aws-credentials",
                    "aws-prod-decoy",
                    100.0,
                )
                .expect_err("relative log path should fail closed");

            assert_eq!(err.to_string(), "Audit operation failed");
        });
    }
}
