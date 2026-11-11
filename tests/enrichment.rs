//! The behaviour of the verification against a local mock server.

#![cfg(feature = "abuseipdb")]

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use badbots::{
    AbuseIpdbConfig, ApiKey, BadBots, Classification, Config, ProviderError, ProviderId,
    VerdictReason,
};
use common::{TestClock, fixture, render};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn other_ip() -> IpAddr {
    "45.32.1.2".parse().unwrap()
}

fn config(base_url: &str) -> Config {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("test-key")),
        daily_quota: None,
        base_url: Some(base_url.to_string()),
        max_age_days: None,
    });
    config
}

async fn serve(name: &str) -> MockServer {
    let server = MockServer::start().await;
    let body = render(
        &fixture(&format!("abuseipdb/{name}")),
        OffsetDateTime::now_utc(),
    );
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    server
}

async fn requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("the requests are recorded")
        .len()
}

#[tokio::test]
async fn the_verification_reports_the_evidence_of_the_provider() {
    let server = serve("web_app_attack.json").await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
    assert_eq!(verdict.coverage.definitive, vec![ProviderId::ABUSEIPDB]);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].provider, ProviderId::ABUSEIPDB);
}

#[tokio::test]
async fn the_assessment_does_not_wait_for_the_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    let started = Instant::now();
    let verdict = bots.assess_ip(ip());
    let elapsed = started.elapsed();

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
    assert!(
        elapsed < Duration::from_secs(5),
        "the assessment waited for the upstream: {elapsed:?}"
    );
}

#[tokio::test]
async fn the_injected_client_performs_the_request_of_the_verification() {
    let server = serve("web_app_attack.json").await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .http_client(common::client())
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn a_library_built_outside_a_runtime_verifies_on_one() {
    let server = serve("web_app_attack.json").await;
    let base_url = format!("{}/api/v2", server.uri());
    let bots = std::thread::spawn(move || {
        BadBots::builder()
            .config(config(&base_url))
            .build()
            .expect("the library is built")
    })
    .join()
    .expect("the thread finishes");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn a_lookup_that_never_answers_times_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .request_timeout(Duration::from_millis(200))
        .build()
        .expect("the library is built");

    let started = Instant::now();
    let verdict = bots.verify_ip(ip()).await;
    let elapsed = started.elapsed();

    assert_eq!(verdict.coverage.failed.len(), 1);
    assert_eq!(verdict.coverage.failed[0].0, ProviderId::ABUSEIPDB);
    assert!(matches!(
        verdict.coverage.failed[0].1,
        ProviderError::Timeout
    ));
    assert!(
        elapsed < Duration::from_secs(5),
        "the lookup took {elapsed:?}"
    );
}

#[tokio::test]
async fn a_rate_limited_provider_is_cooled_down() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "60"))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    let first = bots.verify_ip(ip()).await;
    assert!(matches!(
        first.coverage.failed[0].1,
        ProviderError::RateLimited { .. }
    ));

    let second = bots.verify_ip(other_ip()).await;
    assert!(matches!(
        second.coverage.failed[0].1,
        ProviderError::RateLimited { .. }
    ));

    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn concurrent_lookups_are_collapsed_into_one_request() {
    let server = serve("web_app_attack.json").await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    let mut handles = Vec::new();
    for _ in 0..16 {
        let bots = bots.clone();
        handles.push(tokio::spawn(async move { bots.verify_ip(ip()).await }));
    }

    for handle in handles {
        let verdict = handle.await.expect("the task finishes");
        assert_eq!(verdict.classification, Classification::Bad);
    }

    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn the_budget_guard_stops_the_provider() {
    let server = serve("web_app_attack.json").await;
    let mut config = config(&format!("{}/api/v2", server.uri()));
    config.providers.abuseipdb.as_mut().unwrap().daily_quota = Some(1);

    let bots = BadBots::builder()
        .config(config)
        .build()
        .expect("the library is built");

    let first = bots.verify_ip(ip()).await;
    assert!(first.coverage.failed.is_empty());
    assert_eq!(first.classification, Classification::Bad);

    let second = bots.verify_ip(other_ip()).await;
    assert_eq!(second.coverage.failed.len(), 1);
    assert_eq!(second.coverage.failed[0].0, ProviderId::ABUSEIPDB);
    assert!(matches!(
        second.coverage.failed[0].1,
        ProviderError::QuotaExhausted
    ));

    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn a_negative_result_is_reused_until_the_negative_ttl_elapses() {
    let server = serve("no_reports.json").await;
    let clock = TestClock::new(OffsetDateTime::now_utc());
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .negative_ttl(Duration::from_secs(3_600))
        .build()
        .expect("the library is built");

    let first = bots.verify_ip(ip()).await;
    assert_eq!(first.classification, Classification::Unknown);
    assert_eq!(first.reason, VerdictReason::NoEvidence);

    let second = bots.verify_ip(ip()).await;
    assert_eq!(second.reason, VerdictReason::NoEvidence);
    assert_eq!(requests(&server).await, 1);

    clock.advance(Duration::from_secs(7_200));
    let third = bots.verify_ip(ip()).await;
    assert_eq!(third.reason, VerdictReason::NoEvidence);
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn the_injected_clock_reaches_the_provider() {
    let server = serve("web_app_attack.json").await;
    let clock = TestClock::new(OffsetDateTime::now_utc());
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    let statuses = bots.provider_status();
    assert_eq!(statuses[0].quota_used, Some(1));
    assert_eq!(
        statuses[0].last_attempt,
        Some(clock.instant()),
        "the attempt is recorded against the injected clock"
    );
}

#[tokio::test]
async fn a_failure_belongs_to_the_address_it_happened_for() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    let failed = bots.assess_ip(ip());
    assert_eq!(failed.coverage.failed.len(), 1);

    let other = bots.assess_ip(other_ip());
    assert!(
        other.coverage.failed.is_empty(),
        "a failure of one address is reported for another address"
    );
}

#[tokio::test]
async fn the_provider_health_is_reported() {
    let server = serve("web_app_attack.json").await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    let statuses = bots.provider_status();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].provider, ProviderId::ABUSEIPDB);
    assert_eq!(statuses[0].capability, badbots::ProviderCapability::Primary);
    assert!(statuses[0].enabled);
    assert!(statuses[0].last_attempt.is_some());
    assert!(statuses[0].last_success.is_some());
    assert!(statuses[0].last_error.is_none());
    assert_eq!(statuses[0].quota_limit, Some(1_000));
    assert_eq!(statuses[0].quota_used, Some(1));
}

#[tokio::test]
async fn a_failing_provider_is_reported_in_the_health() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;
    assert_eq!(verdict.coverage.failed.len(), 1);
    assert!(matches!(
        verdict.coverage.failed[0].1,
        ProviderError::Status { code: 500 }
    ));

    let statuses = bots.provider_status();
    assert_eq!(
        statuses[0].last_error,
        Some(ProviderError::Status { code: 500 })
    );
    assert!(statuses[0].last_success.is_none());
}
