//! Timing and clock helpers shared by correlation internals.

use crate::error_codes::COR_DATA_INGEST_FAILED;
use palisade_errors::AgentError;
use std::hint;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const TIMING_SPIN_THRESHOLD: Duration = Duration::from_micros(250);

pub(crate) fn enforce_timing_floor(started: Instant, floor: Duration) {
    let Some(target) = started.checked_add(floor) else {
        return;
    };

    loop {
        let now = Instant::now();
        if now >= target {
            break;
        }

        let remaining = target.saturating_duration_since(now);
        if remaining > TIMING_SPIN_THRESHOLD {
            if let Some(sleep_for) = remaining.checked_sub(TIMING_SPIN_THRESHOLD) {
                thread::sleep(sleep_for);
            }
        } else {
            hint::spin_loop();
        }
    }
}

pub(crate) fn now_secs() -> Result<u64, AgentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            AgentError::new(
                COR_DATA_INGEST_FAILED,
                "Correlation input could not be processed",
                "operation=read_clock; system clock is before Unix epoch",
                "clock",
            )
        })
}
