#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use badbots::Clock;
use time::OffsetDateTime;

/// Builds the HTTP client the tests use.
///
/// The client bypasses the proxy of the environment, because a proxy may
/// rewrite the headers the tests assert on.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .no_proxy()
        .build()
        .expect("the client is built")
}

/// Reads a fixture file.
pub fn fixture(path: &str) -> String {
    let path = fixture_path(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("fixture {} could not be read: {error}", path.display()))
}

/// Reads a fixture file that holds bytes.
pub fn fixture_bytes(path: &str) -> Vec<u8> {
    let path = fixture_path(path);
    std::fs::read(&path)
        .unwrap_or_else(|error| panic!("fixture {} could not be read: {error}", path.display()))
}

/// The path of a fixture file.
fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(path)
}

/// Replaces the timestamp placeholders of a fixture with the given instant.
pub fn render(template: &str, now: OffsetDateTime) -> String {
    let stamp = now
        .format(&time::format_description::well_known::Rfc3339)
        .expect("the instant is representable");
    template
        .replace("{{last_reported_at}}", &stamp)
        .replace("{{last_seen}}", &stamp)
}

/// A clock the test controls.
#[derive(Clone)]
pub struct TestClock {
    instant: Arc<Mutex<OffsetDateTime>>,
}

impl TestClock {
    /// Creates a clock frozen at the given instant.
    pub fn new(now: OffsetDateTime) -> Self {
        Self {
            instant: Arc::new(Mutex::new(now)),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, by: std::time::Duration) {
        let mut instant = self.instant.lock().expect("the clock is not poisoned");
        *instant += time::Duration::seconds(by.as_secs() as i64);
    }

    /// The instant the clock reports.
    pub fn instant(&self) -> OffsetDateTime {
        *self.instant.lock().expect("the clock is not poisoned")
    }
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.instant.lock().expect("the clock is not poisoned")
    }
}
