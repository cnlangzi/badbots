//! The worker thread of the library.

use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use badbots::{BadBots, Config};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn bots() -> BadBots {
    BadBots::builder()
        .config(Config::default())
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
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        thread_count() > before,
        "the verification did not start a worker thread"
    );

    drop(bots);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        thread_count(),
        before,
        "the worker thread outlived the last handle"
    );
}
