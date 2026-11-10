//! The Blocklist.de adapter against checked-in fixtures.

#![cfg(feature = "blocklist_de")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use badbots::provider::blocklist_de::{
    BlocklistDeListProvider, BlocklistDeQueryProvider, MIN_ATTACK_EVENTS, SERVICES,
};
use badbots::provider::lookup::{ProviderRuntime, daily_guard};
use badbots::provider::{FeedProvider, LookupProvider, ProviderCapability};
use badbots::{
    Assertion, EvidenceStrength, MatchScope, ProviderError, ProviderId, SourceFamily,
    ThreatCategory,
};
use common::{TestClock, fixture, fixture_bytes};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn runtime() -> Arc<ProviderRuntime> {
    let client = common::client();
    Arc::new(ProviderRuntime::new(
        client,
        daily_guard(1_000),
        Duration::from_secs(5),
        Arc::new(TestClock::new(now())),
    ))
}

async fn query_provider_for(body: &str) -> (MockServer, BlocklistDeQueryProvider) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body.to_string()))
        .mount(&server)
        .await;

    let provider =
        BlocklistDeQueryProvider::new(server.uri(), Duration::from_secs(48 * 60 * 60), runtime());

    (server, provider)
}

async fn list_provider_for(services: Vec<&str>) -> (MockServer, BlocklistDeListProvider) {
    let server = MockServer::start().await;

    for service in &services {
        Mock::given(method("GET"))
            .and(path(format!("/lists/{service}.txt")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-encoding", "gzip")
                    .set_body_bytes(fixture_bytes(&format!("blocklist_de/{service}.txt.gz"))),
            )
            .mount(&server)
            .await;
    }

    let provider = BlocklistDeListProvider::with_services(
        server.uri(),
        services.iter().map(|service| service.to_string()).collect(),
        Duration::from_secs(30 * 60),
        runtime(),
    );

    (server, provider)
}

#[tokio::test]
async fn the_query_asks_about_the_address_without_a_key() {
    let (server, provider) = query_provider_for(&fixture("blocklist_de/api_attacks.json")).await;
    provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect("the query succeeds");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1);

    let request = &requests[0];
    let query = request.url.query().unwrap_or_default();
    assert!(query.contains("ip=45.32.1.1"));
    assert!(query.contains("start="));
    assert!(query.contains("end="));
    assert!(query.contains("format=json"));
    assert!(!query.contains("key"));
    assert!(!query.contains("api_key"));
}

#[tokio::test]
async fn the_query_window_is_the_forty_eight_hours_before_the_query() {
    let (server, provider) = query_provider_for(&fixture("blocklist_de/api_attacks.json")).await;
    provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect("the query succeeds");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    let query = requests[0].url.query().unwrap_or_default();

    let start = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("start="))
        .and_then(|value| value.parse::<i64>().ok())
        .expect("the start is a timestamp");
    let end = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("end="))
        .and_then(|value| value.parse::<i64>().ok())
        .expect("the end is a timestamp");

    assert_eq!(end - start, 48 * 60 * 60);
    assert_eq!(end, now().unix_timestamp());
}

#[tokio::test]
async fn the_attack_count_is_the_signal_and_the_notifications_are_only_a_value() {
    let (_server, provider) = query_provider_for(&fixture("blocklist_de/api_attacks.json")).await;
    let verdict = provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect("the query succeeds");

    assert_eq!(verdict.provider, ProviderId::BLOCKLIST_DE);
    assert_eq!(verdict.evidence.len(), 1);

    let evidence = &verdict.evidence[0];
    assert_eq!(evidence.count, Some(7));
    assert_eq!(evidence.raw_values.get("attacks").unwrap(), "7");
    assert_eq!(evidence.raw_values.get("reports").unwrap(), "900");
    assert_eq!(evidence.family, SourceFamily::BLOCKLIST_DE);
    assert_eq!(evidence.strength, EvidenceStrength::Corroborating);
    assert_eq!(evidence.scope, MatchScope::Exact);
    assert_eq!(evidence.assertion, Assertion::Attack);
    assert_eq!(evidence.category, ThreatCategory::GenericAbuse);
}

#[tokio::test]
async fn fewer_than_three_attack_events_produce_no_observation() {
    let (_server, provider) =
        query_provider_for(&fixture("blocklist_de/api_two_attacks.json")).await;
    let verdict = provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect("the query succeeds");

    assert!(verdict.evidence.is_empty());
    assert_eq!(MIN_ATTACK_EVENTS, 3);
}

#[tokio::test]
async fn three_attack_events_produce_an_observation_with_a_window_and_an_expiry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{\"attacks\": 3, \"reports\": 0}".to_string()),
        )
        .mount(&server)
        .await;
    let provider =
        BlocklistDeQueryProvider::new(server.uri(), Duration::from_secs(48 * 60 * 60), runtime());

    let verdict = provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect("the query succeeds");
    assert_eq!(verdict.evidence.len(), 1);

    let evidence = &verdict.evidence[0];
    assert_eq!(evidence.count, Some(3));
    assert_eq!(evidence.expires_at, Some(now() + time::Duration::hours(48)));
    let window = evidence.observation_window.expect("the window is reported");
    assert_eq!(window.start, now() - time::Duration::hours(48));
    assert_eq!(window.end, now());
}

#[tokio::test]
async fn an_error_page_is_a_parse_error() {
    let (_server, provider) = query_provider_for(&fixture("blocklist_de/api_malformed.json")).await;
    let error = provider
        .lookup("45.32.1.1".parse().unwrap())
        .await
        .expect_err("the answer is refused");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn the_service_lists_are_read_gzip_compressed() {
    let (server, provider) = list_provider_for(vec!["ssh"]).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers.get("accept-encoding").unwrap(), "gzip");

    assert_eq!(snapshot.entries.len(), 3);
    let addresses: Vec<String> = snapshot
        .entries
        .iter()
        .map(|entry| entry.raw_values.get("address").cloned().unwrap_or_default())
        .collect();
    assert_eq!(addresses, vec!["45.32.1.1", "45.32.1.2", "203.0.113.7"]);
}

#[tokio::test]
async fn a_list_membership_is_only_a_signal() {
    let (_server, provider) = list_provider_for(vec!["ssh"]).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = &snapshot.entries[0];
    assert_eq!(entry.provider, ProviderId::BLOCKLIST_DE_LISTS);
    assert_eq!(entry.family, SourceFamily::BLOCKLIST_DE);
    assert_eq!(entry.strength, EvidenceStrength::Indicative);
    assert_eq!(entry.scope, MatchScope::Exact);
    assert_eq!(entry.category, ThreatCategory::BruteForce);
    assert_eq!(entry.raw_values.get("service").unwrap(), "ssh");
}

#[tokio::test]
async fn the_strong_ips_list_stays_valid_for_seven_days() {
    let (_server, provider) = list_provider_for(vec!["strongips"]).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = &snapshot.entries[0];
    assert_eq!(entry.expires_at, Some(now() + time::Duration::days(7)));
    assert_eq!(entry.category, ThreatCategory::GenericAbuse);
}

#[tokio::test]
async fn the_other_lists_stay_valid_for_two_days() {
    let (_server, provider) = list_provider_for(vec!["ssh"]).await;
    let snapshot = provider.fetch().await.expect("the list is read");

    let entry = &snapshot.entries[0];
    assert_eq!(entry.expires_at, Some(now() + time::Duration::hours(48)));
}

#[tokio::test]
async fn the_provider_declares_its_refresh_interval_and_its_services() {
    let client = common::client();
    let provider = BlocklistDeListProvider::new(
        "http://127.0.0.1:1",
        Duration::from_secs(30 * 60),
        Arc::new(ProviderRuntime::new(
            client,
            daily_guard(1_000),
            Duration::from_secs(5),
            Arc::new(TestClock::new(now())),
        )),
    );

    assert_eq!(
        provider.min_refresh_interval(),
        Duration::from_secs(30 * 60)
    );
    assert_eq!(provider.id(), ProviderId::BLOCKLIST_DE_LISTS);
    assert_eq!(provider.family(), SourceFamily::BLOCKLIST_DE);
    assert_eq!(provider.capability(), ProviderCapability::Corroborating);
    assert_eq!(
        SERVICES,
        &[
            "all",
            "ssh",
            "apache",
            "imap",
            "ftp",
            "sip",
            "bots",
            "bruteforcelogin",
            "strongips"
        ]
    );
}
