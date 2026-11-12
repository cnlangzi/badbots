//! The Spamhaus DROP adapter against checked-in fixtures.

#![cfg(feature = "spamhaus")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use badbots::provider::lookup::ProviderRuntime;
use badbots::provider::spamhaus::SpamhausProvider;
use badbots::provider::{FeedProvider, ProviderCapability};
use badbots::{
    Assertion, EvidenceStrength, MatchScope, ProviderError, ProviderId, SourceFamily,
    ThreatCategory, daily_guard,
};
use common::{TestClock, fixture};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn published_at() -> OffsetDateTime {
    datetime!(2025-01-01 00:00:00 UTC)
}

async fn provider_for(v4: &str, v6: &str) -> (MockServer, SpamhausProvider) {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture(v4)))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture(v6)))
        .mount(&server)
        .await;

    let client = common::client();
    let runtime = Arc::new(ProviderRuntime::new(
        client,
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ));
    let provider = SpamhausProvider::new(server.uri(), Duration::from_secs(60 * 60), runtime);

    (server, provider)
}

#[tokio::test]
async fn the_two_json_lists_are_read() {
    let (server, provider) = provider_for("spamhaus/drop_v4.json", "spamhaus/drop_v6.json").await;
    provider.fetch().await.expect("the lists are read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();

    assert_eq!(paths, vec!["/drop_v4.json", "/drop_v6.json"]);
}

#[tokio::test]
async fn the_metadata_object_is_no_entry() {
    let (server, provider) = provider_for("spamhaus/drop_v4.json", "spamhaus/drop_v6.json").await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    assert_eq!(snapshot.entries.len(), 3);
    assert_eq!(snapshot.published_at, Some(published_at()));
    let _ = server;
}

#[tokio::test]
async fn an_entry_is_a_network_control_observation() {
    let (_server, provider) = provider_for("spamhaus/drop_v4.json", "spamhaus/drop_v6.json").await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    let entry = &snapshot.entries[0];
    assert_eq!(entry.provider, ProviderId::SPAMHAUS);
    assert_eq!(entry.family, SourceFamily::SPAMHAUS);
    assert_eq!(entry.assertion, Assertion::NetworkControl);
    assert_eq!(entry.category, ThreatCategory::MaliciousNetwork);
    assert_eq!(entry.strength, EvidenceStrength::Corroborating);
    assert_eq!(
        entry.scope,
        MatchScope::Prefix {
            network: "1.10.16.0/20".parse().unwrap()
        }
    );
    assert_eq!(entry.published_at, Some(published_at()));
    assert_eq!(
        entry.expires_at,
        Some(published_at() + time::Duration::hours(26))
    );
    assert_eq!(entry.upstream_values.get("sblid").unwrap(), "SBL256894");
    assert_eq!(entry.upstream_values.get("rir").unwrap(), "apinc");
}

#[tokio::test]
async fn the_attribution_carries_the_copyright_and_the_terms() {
    let (_server, provider) = provider_for("spamhaus/drop_v4.json", "spamhaus/drop_v6.json").await;
    let snapshot = provider.fetch().await.expect("the lists are read");

    assert!(snapshot.attribution.contains("The Spamhaus Project"));
    assert!(
        snapshot
            .attribution
            .contains("https://www.spamhaus.org/drop/faq")
    );
}

#[tokio::test]
async fn the_provider_declares_its_refresh_interval() {
    let (_server, provider) = provider_for("spamhaus/drop_v4.json", "spamhaus/drop_v6.json").await;

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(provider.id(), ProviderId::SPAMHAUS);
    assert_eq!(provider.family(), SourceFamily::SPAMHAUS);
    assert_eq!(provider.capability(), ProviderCapability::Corroborating);
}

#[tokio::test]
async fn a_malformed_line_is_a_parse_error() {
    let (_server, provider) =
        provider_for("spamhaus/malformed.json", "spamhaus/drop_v6.json").await;
    let error = provider.fetch().await.expect_err("the list is refused");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn an_empty_list_is_a_parse_error() {
    let (_server, provider) = provider_for("spamhaus/empty.json", "spamhaus/drop_v6.json").await;
    let error = provider.fetch().await.expect_err("the list is refused");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn a_forbidden_answer_is_reported_with_its_status_code() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = common::client();
    let runtime = Arc::new(ProviderRuntime::new(
        client,
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ));
    let provider = SpamhausProvider::new(server.uri(), Duration::from_secs(60 * 60), runtime);

    let error = provider.fetch().await.expect_err("the list is refused");
    assert_eq!(error, ProviderError::Status { code: 403 });
}
