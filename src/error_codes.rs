//! Internal numeric error-code mappings aligned with `palisade-errors` 2.0.

/// `CFG_CONVERSION_FAILED` in the shared Palisade configuration namespace.
pub(crate) const CFG_CONVERSION_FAILED: u16 = 121;

/// `COR_RULE_EVAL_FAILED` in the shared Palisade correlation namespace.
pub(crate) const COR_RULE_EVAL_FAILED: u16 = 400;

/// `COR_BUFFER_OVERFLOW` in the shared Palisade correlation namespace.
pub(crate) const COR_BUFFER_OVERFLOW: u16 = 401;

/// `COR_INVALID_SCORE` in the shared Palisade correlation namespace.
pub(crate) const COR_INVALID_SCORE: u16 = 402;

/// `COR_DATA_INGEST_FAILED` in the shared Palisade correlation namespace.
pub(crate) const COR_DATA_INGEST_FAILED: u16 = 406;

/// `COR_CONTEXT_LOAD_FAILED` in the shared Palisade correlation namespace.
pub(crate) const COR_CONTEXT_LOAD_FAILED: u16 = 411;

/// `COR_RULE_UPDATE_FAILED` in the shared Palisade correlation namespace.
#[cfg(feature = "log")]
pub(crate) const COR_RULE_UPDATE_FAILED: u16 = 422;

/// `COR_VALIDATION_FAILED` in the shared Palisade correlation namespace.
pub(crate) const COR_VALIDATION_FAILED: u16 = 423;

/// `LOG_FILE_WRITE_FAILED` in the shared Palisade logging namespace.
#[cfg(feature = "log")]
pub(crate) const LOG_FILE_WRITE_FAILED: u16 = 611;
