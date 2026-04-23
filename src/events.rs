//! Borrowed event input validation for the hardened correlation engine.

use crate::error_codes::{COR_DATA_INGEST_FAILED, COR_VALIDATION_FAILED};
use chrono::{Timelike, Utc};
use heapless::String as HString;
use palisade_errors::AgentError;
use std::fmt::Write as _;
use std::net::IpAddr;

pub(crate) const MAX_SESSION_ID_LEN: usize = 128;
pub(crate) const MAX_LABEL_LEN: usize = 64;
pub(crate) const MAX_TEXT_FIELD_LEN: usize = 256;
pub(crate) const MAX_PATH_FIELD_LEN: usize = 512;
pub(crate) const MAX_PORT_LIST_LEN: usize = 128;
pub(crate) const MAX_PROTOCOL_LEN: usize = 16;
pub(crate) const MAX_HASH_LEN: usize = 128;
pub(crate) const MAX_ANCESTRY_DEPTH: usize = 64;
const MAX_INTERNAL_ERROR_LEN: usize = 160;

pub(crate) const OBSERVED_ARTIFACT_ACCESS: u8 = 1;
pub(crate) const OBSERVED_SUSPICIOUS_PROCESS: u8 = 2;
pub(crate) const OBSERVED_RAPID_ENUMERATION: u8 = 3;
pub(crate) const OBSERVED_OFF_HOURS_ACTIVITY: u8 = 4;
pub(crate) const OBSERVED_SUSPICIOUS_ANCESTRY: u8 = 5;
pub(crate) const OBSERVED_AUTHENTICATION_FAILURE: u8 = 6;
pub(crate) const OBSERVED_PATH_TRAVERSAL: u8 = 7;
pub(crate) const OBSERVED_SQL_INJECTION: u8 = 8;
pub(crate) const OBSERVED_COMMAND_INJECTION: u8 = 9;
pub(crate) const OBSERVED_CONFIGURATION_CHANGE: u8 = 10;
pub(crate) const OBSERVED_ERROR_EVENT: u8 = 11;
pub(crate) const OBSERVED_NETWORK_PROBE: u8 = 12;
pub(crate) const OBSERVED_MALWARE_DOWNLOAD: u8 = 13;
pub(crate) const OBSERVED_C2_COMMUNICATION: u8 = 14;
pub(crate) const OBSERVED_CUSTOM: u8 = 15;

#[derive(Debug)]
pub(crate) struct ObservedSignal {
    pub(crate) observed_kind: u8,
    pub(crate) timestamp_secs: u64,
}

impl ObservedSignal {
    pub(crate) fn new(observed_kind: u8, timestamp_secs: u64) -> Self {
        Self {
            observed_kind,
            timestamp_secs,
        }
    }
}

pub(crate) struct EventContext<'a> {
    pub(crate) source_ip: IpAddr,
    pub(crate) confidence: f64,
    pub(crate) timestamp_secs: u64,
    pub(crate) current_hour: u8,
    pub(crate) kind: EventKind<'a>,
}

pub(crate) enum EventKind<'a> {
    ArtifactAccess {
        artifact_id: &'a str,
        artifact_tag: &'a str,
    },
    SuspiciousProcess {
        process_name: &'a str,
        pid: u32,
    },
    RapidEnumeration {
        target_count: usize,
        time_window_secs: u64,
    },
    OffHoursActivity {
        hour: u8,
    },
    SuspiciousAncestry {
        process_chain: &'a [&'a str],
    },
    AuthenticationFailure {
        username: &'a str,
        method: &'a str,
    },
    PathTraversal {
        attempted_path: &'a str,
    },
    SqlInjection {
        payload: &'a str,
    },
    CommandInjection {
        command: &'a str,
    },
    ConfigurationChange {
        field: &'a str,
        old_value: &'a str,
        new_value: &'a str,
    },
    ErrorEvent {
        error_code: &'a str,
        operation: &'a str,
        category: &'a str,
    },
    NetworkProbe {
        ports: &'a str,
        protocol: &'a str,
    },
    MalwareDownload {
        source: &'a str,
        hash: Option<&'a str>,
    },
    C2Communication {
        destination: &'a str,
        protocol: &'a str,
    },
    Custom {
        type_id: &'a str,
    },
}

impl<'a> EventContext<'a> {
    pub(crate) fn new(
        source_ip: IpAddr,
        session_id: &str,
        confidence: f64,
        kind: EventKind<'a>,
    ) -> Result<Self, AgentError> {
        validate_session_id(session_id)?;
        validate_confidence(confidence)?;
        kind.validate()?;
        let (timestamp_secs, current_hour) = capture_time()?;

        Ok(Self {
            source_ip,
            confidence,
            timestamp_secs,
            current_hour,
            kind,
        })
    }
}

impl EventKind<'_> {
    pub(crate) fn observed_kind_code(&self) -> u8 {
        match self {
            Self::ArtifactAccess { .. } => OBSERVED_ARTIFACT_ACCESS,
            Self::SuspiciousProcess { .. } => OBSERVED_SUSPICIOUS_PROCESS,
            Self::RapidEnumeration { .. } => OBSERVED_RAPID_ENUMERATION,
            Self::OffHoursActivity { .. } => OBSERVED_OFF_HOURS_ACTIVITY,
            Self::SuspiciousAncestry { .. } => OBSERVED_SUSPICIOUS_ANCESTRY,
            Self::AuthenticationFailure { .. } => OBSERVED_AUTHENTICATION_FAILURE,
            Self::PathTraversal { .. } => OBSERVED_PATH_TRAVERSAL,
            Self::SqlInjection { .. } => OBSERVED_SQL_INJECTION,
            Self::CommandInjection { .. } => OBSERVED_COMMAND_INJECTION,
            Self::ConfigurationChange { .. } => OBSERVED_CONFIGURATION_CHANGE,
            Self::ErrorEvent { .. } => OBSERVED_ERROR_EVENT,
            Self::NetworkProbe { .. } => OBSERVED_NETWORK_PROBE,
            Self::MalwareDownload { .. } => OBSERVED_MALWARE_DOWNLOAD,
            Self::C2Communication { .. } => OBSERVED_C2_COMMUNICATION,
            Self::Custom { .. } => OBSERVED_CUSTOM,
        }
    }

    fn validate(&self) -> Result<(), AgentError> {
        match self {
            Self::ArtifactAccess {
                artifact_id,
                artifact_tag,
            } => {
                validate_non_empty("artifact_id", artifact_id, MAX_TEXT_FIELD_LEN)?;
                validate_non_empty("artifact_tag", artifact_tag, MAX_TEXT_FIELD_LEN)?;
            }
            Self::SuspiciousProcess { process_name, pid } => {
                validate_non_empty("process_name", process_name, MAX_TEXT_FIELD_LEN)?;
                if *pid == 0 {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; pid must be non-zero",
                        "pid",
                    ));
                }
            }
            Self::RapidEnumeration {
                target_count,
                time_window_secs,
            } => {
                if *target_count == 0 {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; target_count must be non-zero",
                        "target_count",
                    ));
                }
                if *time_window_secs == 0 {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; time_window_secs must be non-zero",
                        "time_window_secs",
                    ));
                }
            }
            Self::OffHoursActivity { hour } => {
                if *hour > 23 {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; hour must be within 0-23",
                        "hour",
                    ));
                }
            }
            Self::SuspiciousAncestry { process_chain } => {
                if process_chain.is_empty() {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; process ancestry must not be empty",
                        "process_chain",
                    ));
                }
                if process_chain.len() > MAX_ANCESTRY_DEPTH {
                    return Err(validation_error(
                        "Correlation input rejected",
                        "operation=validate_event; process ancestry exceeds fixed-capacity limit",
                        "process_chain",
                    ));
                }
                for process_name in *process_chain {
                    validate_non_empty("process_chain", process_name, MAX_TEXT_FIELD_LEN)?;
                }
            }
            Self::AuthenticationFailure { username, method } => {
                validate_non_empty("username", username, MAX_TEXT_FIELD_LEN)?;
                validate_non_empty("method", method, MAX_LABEL_LEN)?;
            }
            Self::PathTraversal { attempted_path } => {
                validate_non_empty("attempted_path", attempted_path, MAX_PATH_FIELD_LEN)?;
            }
            Self::SqlInjection { payload } => {
                validate_non_empty("payload", payload, MAX_TEXT_FIELD_LEN)?;
            }
            Self::CommandInjection { command } => {
                validate_non_empty("command", command, MAX_TEXT_FIELD_LEN)?;
            }
            Self::ConfigurationChange {
                field,
                old_value,
                new_value,
            } => {
                validate_non_empty("field", field, MAX_LABEL_LEN)?;
                validate_len("old_value", old_value, MAX_TEXT_FIELD_LEN)?;
                validate_len("new_value", new_value, MAX_TEXT_FIELD_LEN)?;
            }
            Self::ErrorEvent {
                error_code,
                operation,
                category,
            } => {
                validate_non_empty("error_code", error_code, MAX_LABEL_LEN)?;
                validate_non_empty("operation", operation, MAX_TEXT_FIELD_LEN)?;
                validate_non_empty("category", category, MAX_LABEL_LEN)?;
            }
            Self::NetworkProbe { ports, protocol } => {
                validate_non_empty("ports", ports, MAX_PORT_LIST_LEN)?;
                validate_non_empty("protocol", protocol, MAX_PROTOCOL_LEN)?;
            }
            Self::MalwareDownload { source, hash } => {
                validate_non_empty("source", source, MAX_PATH_FIELD_LEN)?;
                if let Some(hash) = hash {
                    validate_non_empty("hash", hash, MAX_HASH_LEN)?;
                }
            }
            Self::C2Communication {
                destination,
                protocol,
            } => {
                validate_non_empty("destination", destination, MAX_PATH_FIELD_LEN)?;
                validate_non_empty("protocol", protocol, MAX_PROTOCOL_LEN)?;
            }
            Self::Custom { type_id } => {
                validate_non_empty("type_id", type_id, MAX_LABEL_LEN)?;
            }
        }

        Ok(())
    }
}

fn validate_session_id(session_id: &str) -> Result<(), AgentError> {
    validate_non_empty("session_id", session_id, MAX_SESSION_ID_LEN)
}

fn validate_confidence(confidence: f64) -> Result<(), AgentError> {
    if !confidence.is_finite() || !(0.0..=100.0).contains(&confidence) {
        return Err(validation_error(
            "Correlation input rejected",
            "operation=validate_event; confidence must be a finite value in [0.0, 100.0]",
            "confidence",
        ));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str, max_len: usize) -> Result<(), AgentError> {
    if value.is_empty() {
        let mut internal = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut internal,
            "operation=validate_event; field={field}; field must not be empty"
        );
        return Err(validation_error(
            "Correlation input rejected",
            internal.as_str(),
            field,
        ));
    }
    validate_len(field, value, max_len)
}

fn validate_len(field: &str, value: &str, max_len: usize) -> Result<(), AgentError> {
    if value.len() > max_len {
        let mut internal = HString::<MAX_INTERNAL_ERROR_LEN>::new();
        let _ = write!(
            &mut internal,
            "operation=validate_event; field={field}; input exceeds fixed-capacity limit ({max_len} bytes)"
        );
        return Err(validation_error(
            "Correlation input rejected",
            internal.as_str(),
            field,
        ));
    }
    Ok(())
}

fn validation_error(
    external: &'static str,
    internal: &str,
    sensitive: impl AsRef<str>,
) -> AgentError {
    AgentError::new(
        COR_VALIDATION_FAILED,
        external,
        internal,
        sensitive.as_ref(),
    )
}

fn capture_time() -> Result<(u64, u8), AgentError> {
    let now = Utc::now();
    let timestamp_secs = u64::try_from(now.timestamp()).map_err(|_| {
        AgentError::new(
            COR_DATA_INGEST_FAILED,
            "Correlation input could not be processed",
            "operation=capture_event_time; system clock is before Unix epoch",
            "event.timestamp",
        )
    })?;

    Ok((timestamp_secs, now.hour() as u8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_empty_session_id() {
        let result = EventContext::new(
            "127.0.0.1".parse().unwrap(),
            "",
            50.0,
            EventKind::RapidEnumeration {
                target_count: 1,
                time_window_secs: 5,
            },
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_confidence() {
        let result = EventContext::new(
            "127.0.0.1".parse().unwrap(),
            "session-1",
            f64::NAN,
            EventKind::RapidEnumeration {
                target_count: 1,
                time_window_secs: 5,
            },
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_oversized_ancestry() {
        let chain = vec!["proc"; MAX_ANCESTRY_DEPTH + 1];
        let refs = chain.to_vec();
        let result = EventContext::new(
            "127.0.0.1".parse().unwrap(),
            "session-1",
            50.0,
            EventKind::SuspiciousAncestry {
                process_chain: refs.as_slice(),
            },
        );

        assert!(result.is_err());
    }
}
