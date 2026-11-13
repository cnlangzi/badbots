//! The CINS Army list adapter against checked-in fixtures.

#![cfg(feature = "cins")]

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use badbots::provider::cins::{ATTRIBUTION, CinsProvider};
use badbots::provider::lookup::ProviderRuntime;
use badbots::provider::{FeedProvider, ProviderCapability, ProviderStatus};
use badbots::{
    Assertion, BadBots, CinsConfig, Classification, Config, EvidencePolicy, EvidenceStrength,
    MatchScope, ProviderError, ProviderId, SourceFamily, ThreatCategory, VerdictReason,
    daily_guard,
};
use common::{TestClock, fixture};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The path the list is read from.
const LIST_PATH: &str = "/list/ci-badguys.txt";

/// The path the list of the second family is read from.
const OTHER_LIST_PATH: &str = "/Level2_IP_Block_List.txt";

fn now() -> OffsetDateTime {
    datetime!(2026-11-13 12:00:00 UTC)
}

/// The instant of the test that reads a second family.
///
/// The list of the second family states its publication time, so its
/// observations expire 48 hours after that time. The instant has to lie inside
/// that window for the observation of the second family to count.
fn second_family_now() -> OffsetDateTime {
    datetime!(2026-05-14 12:00:00 UTC)
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// The address an observation is about.
fn address_of(entry: &badbots::Evidence) -> Option<&str> {
    entry.upstream_values.get("address").map(String::as_str)
}

/// The addresses the observations of a snapshot are about.
fn addresses_of(snapshot: &badbots::FeedSnapshot) -> Vec<&str> {
    snapshot.entries.iter().filter_map(address_of).collect()
}

/// The observation about an address.
fn observation_of<'a>(
    snapshot: &'a badbots::FeedSnapshot,
    address: &str,
) -> Option<&'a badbots::Evidence> {
    snapshot
        .entries
        .iter()
        .find(|entry| address_of(entry) == Some(address))
}

/// The mock server that serves the list.
async fn server_for(body: &str) -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    server
}

/// A provider that reads the list of the mock server.
async fn provider_for(body: &str) -> (MockServer, CinsProvider) {
    let server = server_for(body).await;

    let runtime = Arc::new(ProviderRuntime::new(
        common::client(),
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ));
    let provider = CinsProvider::new(server.uri(), Duration::from_secs(24 * 60 * 60), runtime);

    (server, provider)
}

/// A library that reads the list of the publisher.
async fn library_for(body: &str) -> (MockServer, BadBots) {
    let server = server_for(body).await;

    let bots = BadBots::builder()
        .config(config_for(&server.uri()))
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    (server, bots)
}

/// The status of the CINS provider.
fn status_of(bots: &BadBots) -> ProviderStatus {
    bots.provider_status()
        .into_iter()
        .find(|status| status.provider == ProviderId::CINS)
        .expect("the provider is reported")
}

/// The configuration of a library that reads the list of the publisher.
fn config_for(base_url: &str) -> Config {
    let mut config = Config::default();
    config.providers.cins = Some(CinsConfig {
        enabled: true,
        min_refresh_interval: None,
        base_url: Some(base_url.to_string()),
    });
    config
}

#[test]
fn the_provider_and_the_family_are_named_cins() {
    assert_eq!(ProviderId::CINS.as_str(), "cins");
    assert_eq!(SourceFamily::CINS.as_str(), "cins");
}

#[tokio::test]
async fn the_list_is_read_without_a_credential() {
    let (server, provider) = provider_for(&fixture("cins/ci-badguys.txt")).await;
    provider.fetch().await.expect("the list is read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();

    assert_eq!(paths, vec![LIST_PATH]);
    for request in &requests {
        assert!(
            request.headers.get("authorization").is_none(),
            "the list is published for everyone and needs no credential"
        );
    }
}

#[tokio::test]
async fn an_address_of_the_list_is_an_attack_observation() {
    let (_server, provider) = provider_for(&fixture("cins/ci-badguys.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");

    assert_eq!(entry.provider, ProviderId::CINS);
    assert_eq!(entry.family, SourceFamily::CINS);
    assert_eq!(entry.assertion, Assertion::Attack);
    assert_eq!(entry.category, ThreatCategory::GenericAbuse);
    assert_eq!(entry.upstream_category, None);
    assert_eq!(entry.strength, EvidenceStrength::Convicting);
    assert_eq!(entry.scope, MatchScope::Exact);
    assert_eq!(entry.observed_at, None);
    assert_eq!(entry.published_at, None);
    assert_eq!(entry.retrieved_at, Some(now()));
    assert_eq!(entry.expires_at, Some(now() + time::Duration::hours(24)));
    assert_eq!(entry.observation_window, None);
    assert_eq!(entry.count, None);
    assert_eq!(
        entry.upstream_values.get("address"),
        Some(&"45.32.1.1".to_string())
    );
}

#[tokio::test]
async fn the_snapshot_carries_the_list() {
    let (_server, provider) = provider_for(&fixture("cins/ci-badguys.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(snapshot.provider, ProviderId::CINS);
    assert_eq!(snapshot.family, SourceFamily::CINS);
    assert_eq!(snapshot.published_at, None);
    assert_eq!(snapshot.retrieved_at, now());
    assert_eq!(snapshot.expires_at, Some(now() + time::Duration::hours(24)));
    assert_eq!(snapshot.attribution, ATTRIBUTION);
    assert!(snapshot.header_lines.is_empty());
    assert_eq!(snapshot.entries.len(), 7);
}

#[tokio::test]
async fn the_header_lines_are_kept_verbatim() {
    let (_server, provider) = provider_for(&fixture("cins/with_header.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(
        snapshot.header_lines,
        vec!["CINS Army list of high-risk IP addresses".to_string()]
    );
    assert_eq!(snapshot.entries.len(), 3);
}

#[tokio::test]
async fn a_range_is_no_observation() {
    let (_server, provider) = provider_for(&fixture("cins/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(addresses_of(&snapshot), vec!["1.12.229.231", "1.15.14.29"]);
}

#[tokio::test]
async fn a_malformed_token_is_no_observation() {
    let (_server, provider) = provider_for(&fixture("cins/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert!(!addresses_of(&snapshot).contains(&"not-an-address"));
}

#[tokio::test]
async fn two_addresses_glued_together_are_no_observation() {
    let (_server, provider) = provider_for(&fixture("cins/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert!(!addresses_of(&snapshot).contains(&"1.169.41.521.193.56.135"));
}

#[tokio::test]
async fn a_list_without_an_address_is_a_parse_error() {
    let (_server, provider) = provider_for(&fixture("cins/no_address.txt")).await;
    let error = provider
        .fetch()
        .await
        .expect_err("the list holds no address");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn an_observation_expires_a_day_after_the_retrieval() {
    let (_server, provider) = provider_for(&fixture("cins/ci-badguys.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");

    assert!(entry.is_valid_at(now() + time::Duration::hours(23)));
    assert!(!entry.is_valid_at(now() + time::Duration::hours(24)));
}

#[tokio::test]
async fn the_provider_declares_its_refresh_interval() {
    let (_server, provider) = provider_for(&fixture("cins/ci-badguys.txt")).await;

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(24 * 60 * 60)
    );
    assert_eq!(provider.id(), ProviderId::CINS);
    assert_eq!(provider.family(), SourceFamily::CINS);
    assert_eq!(provider.capability(), ProviderCapability::Corroborating);
}

#[tokio::test]
async fn the_configured_refresh_interval_overrides_the_default() {
    let server = server_for(&fixture("cins/ci-badguys.txt")).await;

    let runtime = Arc::new(ProviderRuntime::new(
        common::client(),
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ));
    let provider = CinsProvider::new(server.uri(), Duration::from_secs(60 * 60), runtime);

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(60 * 60)
    );
}

#[tokio::test]
async fn a_refresh_inside_the_interval_issues_no_request() {
    let (server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    bots.refresh_feeds().await;
    let report = bots.refresh_feeds().await;

    let result = report
        .results
        .iter()
        .find(|result| result.provider == ProviderId::CINS)
        .expect("the provider is reported");
    assert!(matches!(
        result.result,
        Err(ProviderError::RateLimited { .. })
    ));

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn the_list_alone_never_convicts() {
    let (_server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
    assert!(!verdict.evidence.is_empty());
    assert_eq!(verdict.evidence[0].family, SourceFamily::CINS);
    assert_eq!(
        verdict.evidence[0].strength,
        EvidenceStrength::Corroborating,
        "the engine lowers the strength of a corroborating provider"
    );
    assert!(verdict.coverage.definitive.contains(&ProviderId::CINS));
}

#[cfg(feature = "steeman")]
#[tokio::test]
async fn the_list_and_another_family_convict() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("cins/ci-badguys.txt")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(OTHER_LIST_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("steeman/Level2_IP_Block_List.txt")),
        )
        .mount(&server)
        .await;

    let mut config = config_for(&server.uri());
    config.providers.steeman = Some(badbots::SteemanConfig {
        enabled: true,
        min_refresh_interval: None,
        base_url: Some(server.uri()),
    });

    let bots = BadBots::builder()
        .config(config)
        .clock(Arc::new(TestClock::new(second_family_now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
}

#[tokio::test]
async fn the_list_convicts_under_the_lenient_policy() {
    let server = server_for(&fixture("cins/ci-badguys.txt")).await;

    let bots = BadBots::builder()
        .config(config_for(&server.uri()))
        .evidence_policy(EvidencePolicy::Lenient)
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
}

#[tokio::test]
async fn a_list_that_cannot_be_read_keeps_the_previous_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("cins/ci-badguys.txt")))
        .mount(&server)
        .await;

    let mut config = config_for(&server.uri());
    config.providers.cins = Some(CinsConfig {
        enabled: true,
        min_refresh_interval: Some(Duration::from_secs(60 * 60)),
        base_url: Some(server.uri()),
    });

    let clock = TestClock::new(now());
    let bots = BadBots::builder()
        .config(config)
        .clock(Arc::new(clock.clone()))
        .build()
        .expect("the library is built");

    let report = bots.refresh_feeds().await;
    assert!(report.results.iter().all(|result| result.result.is_ok()));

    clock.advance(Duration::from_secs(60 * 60));
    server.reset().await;
    Mock::given(method("GET"))
        .and(path(LIST_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("cins/no_address.txt")))
        .mount(&server)
        .await;

    let report = bots.refresh_feeds().await;
    let failure = report
        .results
        .iter()
        .find(|result| result.provider == ProviderId::CINS)
        .expect("the provider is reported");
    assert!(matches!(failure.result, Err(ProviderError::Parse(_))));

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].family, SourceFamily::CINS);
}

#[tokio::test]
async fn the_status_reports_the_provider_and_the_next_refresh() {
    let (_server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    bots.refresh_feeds().await;

    let status = status_of(&bots);
    assert_eq!(status.family, SourceFamily::CINS);
    assert_eq!(status.capability, ProviderCapability::Corroborating);
    assert!(status.enabled);
    assert_eq!(status.entries, Some(7));
    assert_eq!(status.published_at, None);
    assert_eq!(
        status.next_refresh_at,
        Some(now() + Duration::from_secs(24 * 60 * 60))
    );
}

#[tokio::test]
async fn the_provider_spends_the_budget_of_the_list_providers() {
    let (_server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    let status = status_of(&bots);

    assert_eq!(status.quota_limit, Some(10_000));
}

#[tokio::test]
async fn the_attribution_of_the_loaded_list_is_reachable() {
    let (_server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    bots.refresh_feeds().await;

    assert_eq!(
        bots.feed_attribution(ProviderId::CINS),
        Some(ATTRIBUTION.to_string())
    );
}

#[tokio::test]
async fn an_address_of_the_other_family_is_only_partially_covered() {
    let (_server, bots) = library_for(&fixture("cins/ci-badguys.txt")).await;

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("2001:db8::1"));
    assert!(verdict.coverage.partial.contains(&ProviderId::CINS));
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
}
