//! The worker thread of the library.

use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use badbots::provider::{LookupProvider, ProviderCapability, ProviderCost, ProviderFinding};
use badbots::{
    BadBots, Config, CoverageLevel, ProviderError, ProviderId, SourceFamily, daily_guard,
};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

/// A provider that answers without a request.
struct SilentProvider;

#[async_trait]
impl LookupProvider for SilentProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("silent")
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("silent")
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Primary
    }

    fn cost(&self) -> ProviderCost {
        ProviderCost::Medium
    }

    async fn lookup(&self, _ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        Ok(ProviderFinding::empty(self.id(), CoverageLevel::Partial))
    }
}

fn bots() -> BadBots {
    BadBots::builder()
        .config(Config::default())
        .lookup_provider(daily_guard(100), |_runtime| SilentProvider)
        .build()
        .expect("the library is built")
}

/// The lock that keeps the tests that count threads apart.
fn guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    let mutex = GUARD.get_or_init(|| Mutex::new(()));
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Waits until the condition holds or the deadline passes.
fn wait_until(mut condition: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("the task directory is readable")
        .count()
}

#[cfg(target_os = "linux")]
#[test]
fn the_worker_thread_starts_with_the_first_verification_and_stops_with_the_last_handle() {
    let _guard = guard();
    let before = thread_count();

    for _ in 0..20 {
        let bots = bots();
        bots.assess_user_agent(Some("curl/8.4.0"));
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        thread_count(),
        before,
        "the bot question started a worker thread"
    );

    let bots = bots();
    bots.assess_ip(ip());
    assert!(
        wait_until(|| thread_count() > before, Duration::from_secs(10)),
        "the verification did not start a worker thread"
    );

    drop(bots);
    assert!(
        wait_until(|| thread_count() == before, Duration::from_secs(10)),
        "the worker thread outlived the last handle"
    );
}
