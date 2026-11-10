//! Rate limiting and provider cooldown.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A token bucket that limits how often a provider is contacted.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_second: f64,
    state: Mutex<BucketState>,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Creates a bucket that allows `capacity` requests and refills at
    /// `refill_per_second`.
    pub fn new(capacity: u32, refill_per_second: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_second,
            state: Mutex::new(BucketState {
                tokens: f64::from(capacity),
                last_refill: Instant::now(),
            }),
        }
    }

    /// Creates a bucket that never limits.
    pub fn unlimited() -> Self {
        Self {
            capacity: f64::MAX,
            refill_per_second: f64::MAX,
            state: Mutex::new(BucketState {
                tokens: f64::MAX,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Takes one token from the bucket.
    ///
    /// Returns `false` when the bucket is empty, in which case no request is
    /// issued.
    pub fn try_acquire(&self) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.refill_per_second).min(self.capacity);
        state.last_refill = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The cooldown of a provider after it asked the caller to slow down.
#[derive(Debug, Default)]
pub struct Cooldown {
    until: Mutex<Option<Instant>>,
}

impl Cooldown {
    /// Creates a cooldown that is not active.
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts the provider into cooldown for the given duration.
    pub fn enter(&self, duration: Duration) {
        let until = Instant::now() + duration;
        let mut guard = match self.until.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(until);
    }

    /// The remaining cooldown, when one is active.
    pub fn remaining(&self) -> Option<Duration> {
        let guard = match self.until.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.and_then(|until| until.checked_duration_since(Instant::now()))
    }

    /// Whether the provider is currently cooling down.
    pub fn is_active(&self) -> bool {
        self.remaining().is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Cooldown, TokenBucket};

    #[test]
    fn an_unlimited_bucket_always_grants_a_token() {
        let bucket = TokenBucket::unlimited();
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
    }

    #[test]
    fn a_bucket_runs_out_of_tokens() {
        let bucket = TokenBucket::new(2, 0.0);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn a_cooldown_expires() {
        let cooldown = Cooldown::new();
        assert!(!cooldown.is_active());
        cooldown.enter(Duration::from_millis(1));
        assert!(cooldown.is_active());
        std::thread::sleep(Duration::from_millis(5));
        assert!(!cooldown.is_active());
    }
}
