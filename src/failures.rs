//! Internal error construction helpers aligned with shared Palisade codes.

use crate::error_codes::{
    CFG_CONVERSION_FAILED, COR_BUFFER_OVERFLOW, COR_CONTEXT_LOAD_FAILED, COR_INVALID_SCORE,
    COR_RULE_EVAL_FAILED,
};
use heapless::String as HString;
use palisade_errors::AgentError;
use std::fmt::Write as _;

pub(crate) const MAX_INTERNAL_ERROR_LEN: usize = 192;

pub(crate) fn buffer_error(internal: &str, sensitive: impl AsRef<str>) -> AgentError {
    AgentError::new(
        COR_BUFFER_OVERFLOW,
        "Correlation engine capacity exceeded",
        internal,
        sensitive.as_ref(),
    )
}

pub(crate) fn config_conversion_error(internal: &str, sensitive: impl AsRef<str>) -> AgentError {
    AgentError::new(
        CFG_CONVERSION_FAILED,
        "Configuration contains an invalid value",
        internal,
        sensitive.as_ref(),
    )
}

pub(crate) fn context_error(internal: &str, sensitive: impl AsRef<str>) -> AgentError {
    AgentError::new(
        COR_CONTEXT_LOAD_FAILED,
        "Correlation context is unavailable",
        internal,
        sensitive.as_ref(),
    )
}

pub(crate) fn invalid_score_error(internal: &str, sensitive: impl AsRef<str>) -> AgentError {
    AgentError::new(
        COR_INVALID_SCORE,
        "Correlation score could not be computed",
        internal,
        sensitive.as_ref(),
    )
}

pub(crate) fn rule_evaluation_error(internal: &str, sensitive: impl AsRef<str>) -> AgentError {
    AgentError::new(
        COR_RULE_EVAL_FAILED,
        "Correlation rule evaluation failed",
        internal,
        sensitive.as_ref(),
    )
}

pub(crate) fn severity_rule_error_message(severity_code: u8) -> HString<MAX_INTERNAL_ERROR_LEN> {
    let mut message = HString::<MAX_INTERNAL_ERROR_LEN>::new();
    let _ = write!(
        &mut message,
        "operation=resolve_severity_rule; unsupported severity code {severity_code}"
    );
    message
}
