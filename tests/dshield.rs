//! The DShield adapter against checked-in fixtures.

#![cfg(feature = "dshield")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use badbots::provider::dshield::DShieldProvider;
use badbots::provider::lookup::{ProviderRuntime, daily_guard};
use badbots::provider::{FeedProvider, ProviderCapability};
use badbots::{Assertion, EvidenceStrength, MatchScope, ProviderId, SourceFamily, ThreatCategory};
use common::{TestClock, fixture};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn published_at() -> OffsetDateTime {
    datetime!(2025-01-01 03:00:00 UTC)
}

/// The observation about an address.
fn observation_of<'a>(
    snapshot: &'a badbots::FeedSnapshot,
    address: &str,
) -> Option<&'a badbots::Evidence> {
    snapshot
        .entries
        .iter()
        .find(|entry| entry.upstream_values.get("address").map(String::as_str) == Some(address))
}

async fn provider_for() -> (MockServer, DShieldProvider) {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/block.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("dshield/block.txt")))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/threatintel.txt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("dshield/threatintel.txt")),
        )
        .mount(&server)
        .await;

    let runtime = Arc::new(ProviderRuntime::new(
        common::client(),
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ));
    let provider = DShieldProvider::new(
        server.uri(),
        "badbots-test/0.1.0 (contact: ops@example.test)",
        Duration::from_secs(60 * 60),
        runtime,
    );

    (server, provider)
}

#[tokio::test]
async fn the_two_lists_are_read() {
    let (server, provider) = provider_for().await;
    provider.fetch().await.expect("the lists are read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();

    assert_eq!(paths, vec!["/block.txt", "/threatintel.txt"]);
}

#[tokio::test]
async fn the_request_identifies_the_operator() {
    let (server, provider) = provider_for().await;
    provider.fetch().await.expect("the lists are read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let agent = requests[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap();

    assert!(!agent.is_empty());
    assert!(agent.contains("ops@example.test"));
}

#[tokio::test]
async fn a_block_record_is_a_reconnaissance_observation() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.upstream_values.get("targets").map(String::as_str) == Some("350"))
        .expect("the record is an observation");

    assert_eq!(entry.provider, ProviderId::DSHIELD);
    assert_eq!(entry.family, SourceFamily::DSHIELD);
    assert_eq!(entry.assertion, Assertion::Reconnaissance);
    assert_eq!(entry.category, ThreatCategory::Scanner);
    assert_eq!(entry.strength, EvidenceStrength::Indicative);
    assert_eq!(entry.count, Some(350));
    assert_eq!(
        entry.scope,
        MatchScope::Prefix {
            network: "66.132.186.0/24".parse().unwrap()
        }
    );

    let window = entry.observation_window.expect("the window is reported");
    assert_eq!(window.end, published_at());
    assert_eq!(window.start, published_at() - time::Duration::days(3));
}

#[tokio::test]
async fn a_row_that_is_not_a_record_is_skipped() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    assert!(!snapshot.entries.iter().any(|entry| {
        entry.upstream_values.get("targets").map(String::as_str) == Some("not-a-number")
    }));
}

#[tokio::test]
async fn an_address_that_was_last_seen_long_ago_is_no_observation() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    assert!(observation_of(&snapshot, "45.32.1.99").is_none());
}

#[tokio::test]
async fn the_last_seen_date_becomes_the_observation_time() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");

    assert_eq!(entry.observed_at, Some(datetime!(2025-01-01 00:00:00 UTC)));
    assert_eq!(entry.scope, MatchScope::Exact);
}

#[tokio::test]
async fn the_labels_that_name_an_attack_are_read() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let ssh = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");
    assert_eq!(ssh.assertion, Assertion::Attack);
    assert_eq!(ssh.strength, EvidenceStrength::Corroborating);
    assert_eq!(ssh.family, SourceFamily::DSHIELD);
    assert_eq!(ssh.category, ThreatCategory::BruteForce);

    let scanner = observation_of(&snapshot, "45.32.1.2").expect("the address is an observation");
    assert_eq!(scanner.assertion, Assertion::Attack);
    assert_eq!(scanner.strength, EvidenceStrength::Corroborating);
    assert_eq!(scanner.category, ThreatCategory::Scanner);

    let spam = observation_of(&snapshot, "45.32.1.3").expect("the address is an observation");
    assert_eq!(spam.assertion, Assertion::Abuse);
    assert_eq!(spam.strength, EvidenceStrength::Indicative);
    assert_eq!(spam.category, ThreatCategory::SpamAbuse);
}

#[tokio::test]
async fn a_label_of_another_publisher_keeps_that_lineage() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let entry = observation_of(&snapshot, "45.32.1.4").expect("the address is an observation");

    assert_eq!(entry.family, SourceFamily::BLOCKLIST_DE);
    assert_eq!(entry.strength, EvidenceStrength::Indicative);
    assert_eq!(entry.category, ThreatCategory::WebAttack);
}

#[tokio::test]
async fn a_label_that_names_a_port_carries_the_service_of_that_port() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let ssh = observation_of(&snapshot, "45.32.1.5").expect("the address is an observation");
    assert_eq!(ssh.family, SourceFamily::BLOCKLIST_DE);
    assert_eq!(ssh.category, ThreatCategory::BruteForce);

    let web = observation_of(&snapshot, "45.32.1.6").expect("the address is an observation");
    assert_eq!(web.category, ThreatCategory::WebAttack);
}

#[tokio::test]
async fn the_labels_that_describe_a_context_are_not_observations() {
    let (_server, provider) = provider_for().await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    for address in [
        "45.32.1.7",
        "45.32.1.8",
        "45.32.1.9",
        "45.32.1.10",
        "45.32.1.11",
        "45.32.1.12",
        "45.32.1.13",
        "45.32.1.14",
        "45.32.1.15",
    ] {
        assert!(
            observation_of(&snapshot, address).is_none(),
            "{address} is no observation"
        );
    }
}

#[tokio::test]
async fn the_provider_declares_its_refresh_interval() {
    let (_server, provider) = provider_for().await;

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(provider.id(), ProviderId::DSHIELD);
    assert_eq!(provider.family(), SourceFamily::DSHIELD);
    assert_eq!(provider.capability(), ProviderCapability::Corroborating);
}
