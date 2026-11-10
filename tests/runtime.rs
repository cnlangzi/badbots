//! The behaviour of the library that does not depend on a provider.

mod common;

use std::net::IpAddr;
use std::path::PathBuf;

use badbots::{BadBots, Classification, Config, VerdictReason};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn bots() -> BadBots {
    BadBots::builder()
        .config(Config::default())
        .build()
        .expect("the library is built")
}

#[test]
fn the_assessment_answers_from_local_state_only() {
    let bots = bots();
    let verdict = bots.assess_ip(ip());

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
    assert!(verdict.coverage.definitive.is_empty());
    assert!(verdict.coverage.partial.is_empty());
    assert!(verdict.evidence.is_empty());
}

#[test]
fn a_non_routable_address_is_not_assessed() {
    let bots = bots();

    for address in ["127.0.0.1", "10.0.0.1", "::1", "fe80::1"] {
        let verdict = bots.assess_ip(address.parse().unwrap());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoCoverage);
    }
}

#[test]
fn the_user_agent_does_not_change_the_address_verdict() {
    let bots = bots();
    let request = bots.assess_request(
        ip(),
        Some("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    );

    assert_eq!(request.ip.classification, Classification::Unknown);
    assert_eq!(request.ip.reason, VerdictReason::NoCoverage);
    assert!(request.bot.is_bot);
    assert_eq!(request.bot.claimed_family.as_deref(), Some("Googlebot"));
}

#[test]
fn a_missing_user_agent_is_not_a_bot() {
    let bots = bots();
    let request = bots.assess_request(ip(), None);

    assert!(!request.bot.is_bot);
    assert_eq!(request.bot.ua_state, badbots::UaState::Missing);
}

#[test]
fn the_library_creates_no_thread() {
    #[cfg(target_os = "linux")]
    {
        let before = thread_count();
        for _ in 0..20 {
            let _bots = bots();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        let after = thread_count();

        assert!(
            after <= before + 1,
            "the library created {after} threads, {before} before"
        );
    }
}

#[cfg(target_os = "linux")]
fn thread_count() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("the task directory is readable")
        .count()
}

#[test]
fn the_library_creates_no_background_task() {
    let mut sources = Vec::new();
    collect_sources(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );

    for source in sources {
        let library = source.split("#[cfg(test)]").next().unwrap_or_default();
        for forbidden in ["tokio::spawn", "thread::spawn", "tokio::time::interval"] {
            assert!(
                !library.contains(forbidden),
                "the library must not contain {forbidden}"
            );
        }
    }
}

fn collect_sources(directory: &PathBuf, sources: &mut Vec<String>) {
    let entries = std::fs::read_dir(directory).expect("the source directory is readable");
    for entry in entries {
        let path = entry.expect("the entry is readable").path();
        if path.is_dir() {
            collect_sources(&path, sources);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(std::fs::read_to_string(&path).expect("the source is readable"));
        }
    }
}

#[test]
fn the_classification_has_three_variants() {
    let name = match Classification::Bad {
        Classification::Bad => "bad",
        Classification::Suspect => "suspect",
        Classification::Unknown => "unknown",
    };
    assert_eq!(name, "bad");
}
