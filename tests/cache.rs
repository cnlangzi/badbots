//! The bounds the host sets on the reuse of a cached result.

#![cfg(feature = "abuseipdb")]

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use badbots::{AbuseIpdbConfig, ApiKey, BadBots, Config, ProviderError, ProviderId};
use common::{TestClock, fixture, render};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
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

async fn serve(name: &str, reported_at: OffsetDateTime) -> MockServer {
    let server = MockServer::start().await;
    let body = render(&fixture(&format!("abuseipdb/{name}")), reported_at);
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    server
}

async fn failing_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(500))
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
async fn an_answer_expires_at_the_declared_expiry_when_that_is_the_earlier_one() {
    let now = OffsetDateTime::now_utc();
    let server = serve("web_app_attack.json", now - time::Duration::days(1)).await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    // The upstream declares an expiry 29 days from now, the host bound is 30
    // days, so the declared expiry is the earlier of the two.
    clock.advance(Duration::from_secs(29 * 24 * 60 * 60 - 60));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 1);

    clock.advance(Duration::from_secs(120));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn an_answer_with_evidence_expires_at_the_host_bound_when_it_is_the_earlier_one() {
    let now = OffsetDateTime::now_utc();
    let server = serve("web_app_attack.json", now).await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .positive_ttl(Duration::from_secs(3_600))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    // The upstream declares an expiry 30 days from now, the host bound is one
    // hour, so the host bound is the earlier of the two and the answer is
    // re-fetched when the positive bound elapses.
    clock.advance(Duration::from_secs(3_599));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 1);

    clock.advance(Duration::from_secs(2));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn a_negative_result_is_reused_until_the_negative_bound_elapses() {
    let now = OffsetDateTime::now_utc();
    let server = serve("no_reports.json", now).await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .negative_ttl(Duration::from_secs(3_600))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    clock.advance(Duration::from_secs(3_599));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 1);

    clock.advance(Duration::from_secs(2));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn a_failure_is_not_asked_again_inside_the_failure_window() {
    let now = OffsetDateTime::now_utc();
    let server = failing_server().await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .failure_ttl(Duration::from_secs(300))
        .build()
        .expect("the library is built");

    let first = bots.verify_ip(ip()).await;
    assert!(matches!(
        first.coverage.failed[0].1,
        ProviderError::Status { code: 500 }
    ));

    clock.advance(Duration::from_secs(60));
    let second = bots.verify_ip(ip()).await;
    assert!(matches!(
        second.coverage.failed[0].1,
        ProviderError::Status { code: 500 }
    ));

    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn a_failure_is_asked_again_after_the_failure_window() {
    let now = OffsetDateTime::now_utc();
    let server = failing_server().await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .failure_ttl(Duration::from_secs(300))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    clock.advance(Duration::from_secs(301));
    bots.verify_ip(ip()).await;

    assert_eq!(requests(&server).await, 2);
}

#[tokio::test]
async fn a_sub_second_failure_window_is_honoured() {
    let now = OffsetDateTime::now_utc();
    let server = failing_server().await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .failure_ttl(Duration::from_millis(500))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    bots.verify_ip(ip()).await;

    assert_eq!(requests(&server).await, 1);
}

#[tokio::test]
async fn a_stored_failure_is_reported_by_the_next_assessment() {
    let now = OffsetDateTime::now_utc();
    let server = failing_server().await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .clock(Arc::new(clock.clone()))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    let assessed = bots.assess_ip(ip());
    assert_eq!(assessed.coverage.failed.len(), 1);
    assert_eq!(assessed.coverage.failed[0].0, ProviderId::ABUSEIPDB);
    assert_eq!(
        assessed.coverage.failed[0].1,
        ProviderError::Status { code: 500 }
    );
}

#[tokio::test]
async fn the_builder_sets_every_bound() {
    let now = OffsetDateTime::now_utc();

    let positive = serve("web_app_attack.json", now).await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", positive.uri())))
        .clock(Arc::new(clock.clone()))
        .positive_ttl(Duration::from_secs(3_600))
        .negative_ttl(Duration::from_secs(7_200))
        .failure_ttl(Duration::from_secs(300))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    clock.advance(Duration::from_secs(3_601));
    bots.verify_ip(ip()).await;
    assert_eq!(
        requests(&positive).await,
        2,
        "the positive bound was not applied"
    );

    let negative = serve("no_reports.json", now).await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", negative.uri())))
        .clock(Arc::new(clock.clone()))
        .positive_ttl(Duration::from_secs(3_600))
        .negative_ttl(Duration::from_secs(7_200))
        .failure_ttl(Duration::from_secs(300))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    clock.advance(Duration::from_secs(7_201));
    bots.verify_ip(ip()).await;
    assert_eq!(
        requests(&negative).await,
        2,
        "the negative bound was not applied"
    );

    let failing = failing_server().await;
    let clock = TestClock::new(now);
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", failing.uri())))
        .clock(Arc::new(clock.clone()))
        .positive_ttl(Duration::from_secs(3_600))
        .negative_ttl(Duration::from_secs(7_200))
        .failure_ttl(Duration::from_secs(300))
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    clock.advance(Duration::from_secs(60));
    bots.verify_ip(ip()).await;
    assert_eq!(
        requests(&failing).await,
        1,
        "the failure window was not applied"
    );

    clock.advance(Duration::from_secs(241));
    bots.verify_ip(ip()).await;
    assert_eq!(requests(&failing).await, 2);
}
