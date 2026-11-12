//! The budget of a provider.
//!
//! The upstream quotas of the supported sources are small enough that an
//! accidental call loop would exhaust them, so the library counts the lookups it
//! issues itself and refuses to exceed the configured budget.
//!
//! The budget of an upstream key belongs to every process that spends it, so a
//! host that runs the library in more than one process and shares one key
//! between them implements [`Quota`] itself and hands its budget to the
//! library. [`QuotaGuard`] is the in-process implementation the crate ships.

use std::sync::{Arc, Mutex};

use time::OffsetDateTime;

/// The budget of a provider.
///
/// The implementation decides:
///
/// - that [`try_consume`](Quota::try_consume) is atomic across every caller
///   that shares the budget, because the library asks the budget from its
///   worker thread and several processes of a host may share one budget;
/// - the window the budget is counted over and when that window rolls over;
/// - that [`used`](Quota::used) reports the number of lookups spent in the
///   current window;
/// - that [`bounded_limit`](Quota::bounded_limit) reports `None` when the
///   budget has no limit.
pub trait Quota: Send + Sync {
    /// Spends one lookup of the budget.
    ///
    /// The call has to be atomic across every caller that shares the budget.
    ///
    /// Returns `false` when the budget of the current window is used up, in
    /// which case the caller must not contact the upstream service.
    fn try_consume(&self, now: OffsetDateTime) -> bool;

    /// The number of lookups already spent in the current window.
    fn used(&self, now: OffsetDateTime) -> u32;

    /// The budget of the current window, when the counter has one.
    ///
    /// A counter without a budget has no limit to report.
    fn bounded_limit(&self) -> Option<u32>;
}

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
    unlimited: bool,
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
            unlimited: false,
            state: Mutex::new(QuotaState {
                used: 0,
                period: (0, 0, 0),
            }),
        }
    }

    /// Creates a guard that never refuses a request.
    ///
    /// The guard is used by a provider whose upstream does not count the
    /// requests it receives.
    pub fn unlimited() -> Self {
        Self {
            limit: u32::MAX,
            window: QuotaWindow::Day,
            unlimited: true,
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

    /// The budget of the current window, when the guard has one.
    ///
    /// An unlimited guard has no budget, so it has no limit to report.
    pub fn bounded_limit(&self) -> Option<u32> {
        if self.unlimited {
            return None;
        }
        Some(self.limit)
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
        if self.unlimited {
            state.used = state.used.saturating_add(1);
            return true;
        }
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

impl Quota for QuotaGuard {
    fn try_consume(&self, now: OffsetDateTime) -> bool {
        QuotaGuard::try_consume(self, now)
    }

    fn used(&self, now: OffsetDateTime) -> u32 {
        QuotaGuard::used(self, now)
    }

    fn bounded_limit(&self) -> Option<u32> {
        QuotaGuard::bounded_limit(self)
    }
}

/// The budget of a provider that is counted per day.
pub fn daily_guard(limit: u32) -> Arc<dyn Quota> {
    Arc::new(QuotaGuard::new(limit, QuotaWindow::Day))
}

/// The budget of a provider that is counted per month.
pub fn monthly_guard(limit: u32) -> Arc<dyn Quota> {
    Arc::new(QuotaGuard::new(limit, QuotaWindow::Month))
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{Quota, QuotaGuard, QuotaWindow, daily_guard, monthly_guard};

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

    #[test]
    fn an_unlimited_quota_never_refuses_a_request() {
        let guard = QuotaGuard::unlimited();
        let now = datetime!(2026-01-01 00:00:00 UTC);
        for _ in 0..1_000 {
            assert!(guard.try_consume(now));
        }
        assert_eq!(guard.used(now), 1_000);
        assert_eq!(guard.bounded_limit(), None);
    }

    #[test]
    fn the_guard_answers_the_budget_trait_like_its_own_methods() {
        let guard = QuotaGuard::new(2, QuotaWindow::Day);
        let now = datetime!(2026-01-01 00:00:00 UTC);

        assert!(Quota::try_consume(&guard, now));
        assert!(Quota::try_consume(&guard, now));
        assert!(!Quota::try_consume(&guard, now));
        assert_eq!(Quota::used(&guard, now), QuotaGuard::used(&guard, now));
        assert_eq!(
            Quota::bounded_limit(&guard),
            QuotaGuard::bounded_limit(&guard)
        );
    }

    #[test]
    fn the_daily_and_the_monthly_budget_spend_their_own_window() {
        let now = datetime!(2026-01-01 00:00:00 UTC);
        let next_day = datetime!(2026-01-02 00:00:00 UTC);
        let next_month = datetime!(2026-02-01 00:00:00 UTC);

        let daily = daily_guard(1);
        assert!(daily.try_consume(now));
        assert!(!daily.try_consume(now));
        assert!(daily.try_consume(next_day));

        let monthly = monthly_guard(1);
        assert!(monthly.try_consume(now));
        assert!(!monthly.try_consume(next_day));
        assert!(monthly.try_consume(next_month));
        assert_eq!(monthly.bounded_limit(), Some(1));
    }
}
