#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use badbots::Clock;
use time::OffsetDateTime;

/// Reads a fixture file.
pub fn fixture(path: &str) -> String {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("fixture {} could not be read: {error}", path.display()))
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
}

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        *self.instant.lock().expect("the clock is not poisoned")
    }
}
