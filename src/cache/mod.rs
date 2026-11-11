//! A TTL cache with single-flight.
//!
//! The cache holds the answer of a provider next to the failure of a provider
//! interaction, so a provider that is unreachable is not asked again inside
//! the failure window.
//!
//! The cache is written by hand because a cache crate would create a background
//! maintenance thread, which the no-background-activity constraint forbids.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::Mutex as AsyncMutex;

use crate::bound_expiry;
use crate::error::ProviderError;
use crate::model::ProviderId;

/// The key of a cached lookup.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CacheKey {
    /// The provider that produced the result.
    pub provider: ProviderId,
    /// The assessed address.
    pub ip: IpAddr,
}

/// A cached value and the instant it stops being usable.
#[derive(Clone, Debug)]
pub struct CacheEntry<T> {
    /// The cached value.
    pub value: T,
    /// The instant the value expires.
    pub expires_at: OffsetDateTime,
}

/// What the cache holds for one key.
#[derive(Clone, Debug)]
pub enum CacheValue<T> {
    /// The answer of the provider.
    Answer(T),
    /// The reason the provider gave no answer.
    Failure(ProviderError),
}

/// One cache entry and the lock that guards it.
#[derive(Debug)]
struct Slot<T> {
    entry: AsyncMutex<Option<CacheEntry<CacheValue<T>>>>,
}

/// A cache of lookup results with a bounded capacity.
#[derive(Debug)]
pub struct TtlCache<T> {
    slots: Mutex<HashMap<CacheKey, Arc<Slot<T>>>>,
    capacity: usize,
    failure_ttl: Duration,
}

impl<T: Clone> TtlCache<T> {
    /// Creates a cache that holds at most `capacity` entries.
    ///
    /// A failed lookup is remembered for `failure_ttl`, so a provider that is
    /// unreachable is not asked again inside that window.
    pub fn new(capacity: usize, failure_ttl: Duration) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            capacity,
            failure_ttl,
        }
    }

    /// The number of cached entries.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.slots.lock().map(|slots| slots.len()).unwrap_or(0)
    }

    /// Returns the cached value of a key when it is still usable.
    pub fn get(&self, key: &CacheKey, now: OffsetDateTime) -> Option<CacheValue<T>> {
        let slot = {
            let slots = match self.slots.lock() {
                Ok(slots) => slots,
                Err(poisoned) => poisoned.into_inner(),
            };
            slots.get(key).cloned()
        }?;
        let guard = slot.entry.try_lock().ok()?;
        let entry = guard.as_ref()?;
        if entry.expires_at > now {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    /// Returns the cached value of a key, fetching it when it is missing or
    /// expired.
    ///
    /// Concurrent misses of the same key are collapsed into a single call of
    /// `fetch`. A failed fetch is remembered for the failure window and
    /// returned by the calls that fall inside it, so a provider that is
    /// unreachable is not asked again and again.
    pub async fn get_or_fetch<F, Fut>(
        &self,
        key: CacheKey,
        now: OffsetDateTime,
        fetch: F,
    ) -> Result<T, ProviderError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CacheEntry<T>, ProviderError>>,
    {
        let slot = self.slot(&key);
        let mut guard = slot.entry.lock().await;

        if let Some(entry) = guard.as_ref()
            && entry.expires_at > now
        {
            return match &entry.value {
                CacheValue::Answer(answer) => Ok(answer.clone()),
                CacheValue::Failure(error) => Err(error.clone()),
            };
        }

        let fetched = match fetch().await {
            Ok(fetched) => fetched,
            Err(error) => {
                *guard = Some(CacheEntry {
                    value: CacheValue::Failure(error.clone()),
                    expires_at: bound_expiry(now, self.failure_ttl),
                });
                drop(guard);
                self.enforce_capacity(now, Some(&key));
                return Err(error);
            }
        };
        *guard = Some(CacheEntry {
            value: CacheValue::Answer(fetched.value.clone()),
            expires_at: fetched.expires_at,
        });
        drop(guard);

        self.enforce_capacity(now, Some(&key));

        Ok(fetched.value)
    }

    fn slot(&self, key: &CacheKey) -> Arc<Slot<T>> {
        let mut slots = match self.slots.lock() {
            Ok(slots) => slots,
            Err(poisoned) => poisoned.into_inner(),
        };
        slots
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(Slot {
                    entry: AsyncMutex::new(None),
                })
            })
            .clone()
    }

    /// Drops the entries that no longer carry a usable value until the cache
    /// fits its capacity again.
    ///
    /// A slot that holds no value at all is dropped before a slot that holds a
    /// value, and the entry that expires first is dropped before the others. A
    /// remembered failure is therefore dropped before an answer whenever the
    /// failure window is shorter than the bounds of the answers.
    fn enforce_capacity(&self, now: OffsetDateTime, keep: Option<&CacheKey>) {
        let mut slots = match self.slots.lock() {
            Ok(slots) => slots,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slots.len() <= self.capacity {
            return;
        }

        slots.retain(|key, slot| {
            if keep.is_some_and(|keep| keep == key) {
                return true;
            }
            slot.entry
                .try_lock()
                .ok()
                .and_then(|guard| guard.as_ref().map(|entry| entry.expires_at > now))
                .unwrap_or(true)
        });

        while slots.len() > self.capacity {
            let victim = slots
                .iter()
                .filter(|(key, _)| keep.is_none_or(|keep| keep != *key))
                .filter_map(|(key, slot)| {
                    slot.entry.try_lock().ok().map(|guard| {
                        let rank = match guard.as_ref() {
                            Some(entry) => (1u8, entry.expires_at),
                            None => (0u8, OffsetDateTime::UNIX_EPOCH),
                        };
                        (rank, key.clone())
                    })
                })
                .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)))
                .map(|(_, key)| key);
            match victim {
                Some(key) => {
                    slots.remove(&key);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    use time::{Duration, OffsetDateTime};

    use super::{CacheEntry, CacheKey, CacheValue, TtlCache};
    use crate::error::ProviderError;
    use crate::model::ProviderId;

    fn key(ip: &str) -> CacheKey {
        CacheKey {
            provider: ProviderId::ABUSEIPDB,
            ip: ip.parse::<IpAddr>().unwrap(),
        }
    }

    #[tokio::test]
    async fn a_failed_lookup_stays_within_the_capacity() {
        let cache: TtlCache<u32> = TtlCache::new(2, StdDuration::from_secs(300));
        let now = OffsetDateTime::UNIX_EPOCH;
        for index in 0..10u8 {
            let key = CacheKey {
                provider: ProviderId::ABUSEIPDB,
                ip: IpAddr::from([45, 32, 1, index]),
            };
            let result = cache
                .get_or_fetch(key, now, || async {
                    Err::<CacheEntry<u32>, ProviderError>(ProviderError::Timeout)
                })
                .await;
            assert!(result.is_err());
        }
        assert!(cache.len() <= 2, "the cache grew to {}", cache.len());
    }

    #[tokio::test]
    async fn a_cached_value_is_reused() {
        let cache: TtlCache<u32> = TtlCache::new(10, StdDuration::from_secs(300));
        let now = OffsetDateTime::UNIX_EPOCH;
        let value = cache
            .get_or_fetch(key("45.32.1.1"), now, || async {
                Ok(CacheEntry {
                    value: 7,
                    expires_at: now + Duration::hours(1),
                })
            })
            .await
            .unwrap();
        assert_eq!(value, 7);
        assert!(matches!(
            cache.get(&key("45.32.1.1"), now),
            Some(CacheValue::Answer(7))
        ));
    }

    #[tokio::test]
    async fn an_expired_value_is_fetched_again() {
        let cache: TtlCache<u32> = TtlCache::new(10, StdDuration::from_secs(300));
        let now = OffsetDateTime::UNIX_EPOCH;
        let later = now + Duration::hours(2);
        cache
            .get_or_fetch(key("45.32.1.1"), now, || async {
                Ok(CacheEntry {
                    value: 7,
                    expires_at: now + Duration::hours(1),
                })
            })
            .await
            .unwrap();
        let value = cache
            .get_or_fetch(key("45.32.1.1"), later, || async {
                Ok(CacheEntry {
                    value: 9,
                    expires_at: later + Duration::hours(1),
                })
            })
            .await
            .unwrap();
        assert_eq!(value, 9);
    }

    #[tokio::test]
    async fn a_failure_is_returned_inside_the_failure_window() {
        let cache: TtlCache<u32> = TtlCache::new(10, StdDuration::from_secs(300));
        let now = OffsetDateTime::UNIX_EPOCH;
        let calls = AtomicUsize::new(0);

        for _ in 0..2 {
            let result = cache
                .get_or_fetch(key("45.32.1.1"), now, || async {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err::<CacheEntry<u32>, ProviderError>(ProviderError::Timeout)
                })
                .await;
            assert_eq!(result, Err(ProviderError::Timeout));
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            cache.get(&key("45.32.1.1"), now),
            Some(CacheValue::Failure(ProviderError::Timeout))
        ));
    }

    #[tokio::test]
    async fn a_failure_is_fetched_again_after_the_failure_window() {
        let cache: TtlCache<u32> = TtlCache::new(10, StdDuration::from_secs(300));
        let now = OffsetDateTime::UNIX_EPOCH;
        let later = now + Duration::minutes(6);
        let calls = AtomicUsize::new(0);

        cache
            .get_or_fetch(key("45.32.1.1"), now, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<CacheEntry<u32>, ProviderError>(ProviderError::Timeout)
            })
            .await
            .unwrap_err();
        cache
            .get_or_fetch(key("45.32.1.1"), later, || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<CacheEntry<u32>, ProviderError>(ProviderError::Timeout)
            })
            .await
            .unwrap_err();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_misses_are_collapsed() {
        let cache: Arc<TtlCache<u32>> = Arc::new(TtlCache::new(10, StdDuration::from_secs(300)));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            let calls = Arc::clone(&calls);
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_fetch(
                        key("45.32.1.1"),
                        OffsetDateTime::UNIX_EPOCH,
                        || async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            Ok(CacheEntry {
                                value: 1,
                                expires_at: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
                            })
                        },
                    )
                    .await
                    .unwrap()
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap(), 1);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
