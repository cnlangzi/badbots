//! The steeman adapter against checked-in fixtures.

#![cfg(feature = "steeman")]

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use badbots::provider::lookup::ProviderRuntime;
use badbots::provider::steeman::{ATTRIBUTION, SteemanProvider};
use badbots::provider::{FeedProvider, ProviderCapability, ProviderStatus};
use badbots::{
    Assertion, BadBots, Classification, Config, EvidencePolicy, EvidenceStrength, MatchScope,
    ProviderError, ProviderId, SourceFamily, SteemanConfig, ThreatCategory, VerdictReason,
    daily_guard,
};
use common::{TestClock, fixture};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The path the list is read from.
const LIST_PATH: &str = "/Level2_IP_Block_List.txt";

fn now() -> OffsetDateTime {
    datetime!(2026-11-14 12:00:00 UTC)
}

fn published_at() -> OffsetDateTime {
    datetime!(2026-11-14 03:52:24 UTC)
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
async fn provider_for(body: &str) -> (MockServer, SteemanProvider) {
    provider_for_at(body, now()).await
}

/// A provider that reads the list of the mock server at a given instant.
async fn provider_for_at(body: &str, now: OffsetDateTime) -> (MockServer, SteemanProvider) {
    let server = server_for(body).await;

    let runtime = Arc::new(ProviderRuntime::new(
        common::client(),
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now)),
    ));
    let provider = SteemanProvider::new(server.uri(), Duration::from_secs(24 * 60 * 60), runtime);

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

/// The status of the steeman provider.
fn status_of(bots: &BadBots) -> ProviderStatus {
    bots.provider_status()
        .into_iter()
        .find(|status| status.provider == ProviderId::STEEMAN)
        .expect("the provider is reported")
}

/// The configuration of a library that reads the list of the publisher.
fn config_for(base_url: &str) -> Config {
    let mut config = Config::default();
    config.providers.steeman = Some(SteemanConfig {
        enabled: true,
        min_refresh_interval: None,
        base_url: Some(base_url.to_string()),
    });
    config
}

#[tokio::test]
async fn the_list_is_read() {
    let (server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;
    provider.fetch().await.expect("the list is read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let paths: Vec<String> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();

    assert_eq!(paths, vec!["/Level2_IP_Block_List.txt"]);
}

#[tokio::test]
async fn an_address_of_the_list_is_an_attack_observation() {
    let (_server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");

    assert_eq!(entry.provider, ProviderId::STEEMAN);
    assert_eq!(entry.family, SourceFamily::STEEMAN);
    assert_eq!(entry.assertion, Assertion::Attack);
    assert_eq!(entry.category, ThreatCategory::GenericAbuse);
    assert_eq!(entry.strength, EvidenceStrength::Convicting);
    assert_eq!(entry.scope, MatchScope::Exact);
    assert_eq!(entry.observed_at, None);
    assert_eq!(entry.published_at, Some(published_at()));
    assert_eq!(entry.retrieved_at, Some(now()));
}

#[tokio::test]
async fn the_publication_time_is_read_from_the_header() {
    let (_server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(snapshot.published_at, Some(published_at()));
    assert_eq!(
        snapshot.expires_at,
        Some(published_at() + time::Duration::hours(48))
    );
}

#[tokio::test]
async fn a_header_without_a_time_leaves_the_publication_time_unset() {
    let (_server, provider) = provider_for(&fixture("steeman/no_publication_time.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(snapshot.published_at, None);
    assert_eq!(snapshot.expires_at, Some(now() + time::Duration::hours(48)));
}

#[tokio::test]
async fn the_header_lines_are_kept_verbatim() {
    let (_server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(
        snapshot.header_lines,
        vec![
            "https://jeroen.steeman.org/Level2_IP_Block_List.txt Contains 16469 IP addresses. \
             Last updated: 14/11/2026 03:52:24 UTC"
                .to_string()
        ]
    );
}

#[tokio::test]
async fn a_range_is_no_observation() {
    let (_server, provider) = provider_for(&fixture("steeman/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(addresses_of(&snapshot), vec!["45.32.1.10", "45.32.1.11"]);
}

#[tokio::test]
async fn a_malformed_token_is_no_observation() {
    let (_server, provider) = provider_for(&fixture("steeman/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert!(!addresses_of(&snapshot).contains(&"not-an-address"));
}

#[tokio::test]
async fn two_addresses_glued_together_are_no_observation() {
    let (_server, provider) = provider_for(&fixture("steeman/odd_lines.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert!(!addresses_of(&snapshot).contains(&"45.32.1.1345.32.1.14"));
}

#[tokio::test]
async fn a_list_without_an_address_is_a_parse_error() {
    let (_server, provider) = provider_for(&fixture("steeman/no_address.txt")).await;
    let error = provider
        .fetch()
        .await
        .expect_err("the list holds no address");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn an_observation_of_a_fresh_list_is_valid() {
    let (_server, provider) = provider_for_at(
        &fixture("steeman/Level2_IP_Block_List.txt"),
        published_at() + time::Duration::hours(1),
    )
    .await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");
    assert!(entry.is_valid_at(published_at() + time::Duration::hours(1)));
}

#[tokio::test]
async fn an_observation_of_a_list_that_is_two_days_old_is_no_longer_valid() {
    let two_days_later = published_at() + time::Duration::hours(48);
    let (_server, provider) =
        provider_for_at(&fixture("steeman/Level2_IP_Block_List.txt"), two_days_later).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = observation_of(&snapshot, "45.32.1.1").expect("the address is an observation");
    assert!(!entry.is_valid_at(two_days_later));
}

#[tokio::test]
async fn the_provider_declares_its_refresh_interval() {
    let (_server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(24 * 60 * 60)
    );
    assert_eq!(provider.id(), ProviderId::STEEMAN);
    assert_eq!(provider.family(), SourceFamily::STEEMAN);
    assert_eq!(provider.capability(), ProviderCapability::Corroborating);
}

#[tokio::test]
async fn the_attribution_names_the_publisher_and_his_terms() {
    let (_server, provider) = provider_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    assert_eq!(snapshot.attribution, ATTRIBUTION);
}

#[tokio::test]
async fn the_list_alone_never_convicts() {
    let (_server, bots) = library_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].family, SourceFamily::STEEMAN);
    assert_eq!(
        verdict.evidence[0].strength,
        EvidenceStrength::Corroborating,
        "the engine lowers the strength of a corroborating provider"
    );
}

#[tokio::test]
async fn the_list_convicts_under_the_lenient_policy() {
    let server = server_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

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
async fn the_status_reports_the_provider_and_the_next_refresh() {
    let (_server, bots) = library_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

    bots.refresh_feeds().await;

    let status = status_of(&bots);
    assert_eq!(status.family, SourceFamily::STEEMAN);
    assert_eq!(status.capability, ProviderCapability::Corroborating);
    assert!(status.enabled);
    assert_eq!(status.entries, Some(7));
    assert_eq!(status.published_at, Some(published_at()));
    assert_eq!(
        status.next_refresh_at,
        Some(now() + Duration::from_secs(24 * 60 * 60))
    );
}

#[tokio::test]
async fn the_attribution_of_the_loaded_list_is_reachable() {
    let (_server, bots) = library_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

    bots.refresh_feeds().await;

    assert_eq!(
        bots.feed_attribution(ProviderId::STEEMAN),
        Some(ATTRIBUTION.to_string())
    );
}

#[tokio::test]
async fn an_address_of_the_other_family_is_only_partially_covered() {
    let (_server, bots) = library_for(&fixture("steeman/Level2_IP_Block_List.txt")).await;

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("2001:db8::1"));
    assert!(verdict.coverage.partial.contains(&ProviderId::STEEMAN));
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
}
