//! The local budget guard.
//!
//! The upstream quotas of the supported sources are small enough that an
//! accidental call loop would exhaust them, so the library counts the lookups it
//! issues itself and refuses to exceed the configured budget.

use std::sync::Mutex;

use time::OffsetDateTime;

/// The period a budget is counted over.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QuotaWindow {
    /// The budget is counted per calendar day.
    Day,
    /// The budget is counted per calendar month.
    Month,
}

/// Counts the lookups of one provider against its budget.
#[derive(Debug)]
pub struct QuotaGuard {
    limit: u32,
    window: QuotaWindow,
    state: Mutex<QuotaState>,
}

#[derive(Debug)]
struct QuotaState {
    used: u32,
    period: (i32, u8, u8),
}

impl QuotaGuard {
    /// Creates a guard for the given limit and window.
    pub fn new(limit: u32, window: QuotaWindow) -> Self {
        Self {
            limit,
            window,
            state: Mutex::new(QuotaState {
                used: 0,
                period: (0, 0, 0),
            }),
        }
    }

    /// The budget of the current window.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// The number of lookups already spent in the current window.
    pub fn used(&self, now: OffsetDateTime) -> u32 {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.roll_over(&mut state, now);
        state.used
    }

    /// Spends one lookup of the budget.
    ///
    /// Returns `false` when the budget of the current window is used up, in which
    /// case the caller must not contact the upstream service.
    pub fn try_consume(&self, now: OffsetDateTime) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.roll_over(&mut state, now);
        if state.used >= self.limit {
            return false;
        }
        state.used += 1;
        true
    }

    fn roll_over(&self, state: &mut QuotaState, now: OffsetDateTime) {
        let period = match self.window {
            QuotaWindow::Day => (now.year(), now.month() as u8, now.day()),
            QuotaWindow::Month => (now.year(), now.month() as u8, 0),
        };
        if state.period != period {
            state.period = period;
            state.used = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{QuotaGuard, QuotaWindow};

    #[test]
    fn a_budget_is_spent_within_a_window() {
        let guard = QuotaGuard::new(2, QuotaWindow::Day);
        let now = datetime!(2026-01-01 00:00:00 UTC);
        assert!(guard.try_consume(now));
        assert!(guard.try_consume(now));
        assert!(!guard.try_consume(now));
        assert_eq!(guard.used(now), 2);
    }

    #[test]
    fn a_budget_is_reset_in_the_next_window() {
        let guard = QuotaGuard::new(1, QuotaWindow::Day);
        let first = datetime!(2026-01-01 00:00:00 UTC);
        let second = datetime!(2026-01-02 00:00:00 UTC);
        assert!(guard.try_consume(first));
        assert!(!guard.try_consume(first));
        assert!(guard.try_consume(second));
    }

    #[test]
    fn a_monthly_budget_spans_the_whole_month() {
        let guard = QuotaGuard::new(1, QuotaWindow::Month);
        let first = datetime!(2026-01-01 00:00:00 UTC);
        let second = datetime!(2026-01-31 00:00:00 UTC);
        let third = datetime!(2026-02-01 00:00:00 UTC);
        assert!(guard.try_consume(first));
        assert!(!guard.try_consume(second));
        assert!(guard.try_consume(third));
    }
}
