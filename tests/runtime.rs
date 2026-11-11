//! The behaviour of the library that does not depend on a provider.

use std::net::IpAddr;

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
    let verdict = bots.assess_ip(ip());
    let bot = bots.assess_user_agent(Some(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    ));

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
    assert!(bot.is_bot);
    assert_eq!(bot.claimed_family.as_deref(), Some("Googlebot"));
}

#[test]
fn a_missing_user_agent_is_not_a_bot() {
    let bots = bots();
    let bot = bots.assess_user_agent(None);

    assert!(!bot.is_bot);
    assert_eq!(bot.ua_state, badbots::UaState::Missing);
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
