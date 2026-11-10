//! The clock the library reads the current time from.

use std::sync::Arc;

use time::OffsetDateTime;

/// Supplies the current time.
///
/// A host application can inject a deterministic clock to make expiry and
/// caching behaviour reproducible.
pub trait Clock: Send + Sync {
    /// Returns the current instant in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock that always reports the same instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    instant: OffsetDateTime,
}

impl FixedClock {
    /// Creates a clock frozen at the given instant.
    pub fn new(instant: OffsetDateTime) -> Self {
        Self { instant }
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.instant
    }
}

/// The default clock of the library.
pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}
