//! The AbuseIPDB adapter against checked-in fixtures.

#![cfg(feature = "abuseipdb")]

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use badbots::provider::abuseipdb::AbuseIpdbProvider;
use badbots::provider::lookup::{ProviderRuntime, daily_guard};
use badbots::provider::{LookupProvider, ProviderCapability};
use badbots::{
    ApiKey, CoverageLevel, EvidenceStrength, ProviderError, ProviderId, SourceFamily, Suppression,
};
use common::{fixture, render};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

async fn provider_for(name: &str) -> (MockServer, AbuseIpdbProvider) {
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

    let client = badbots::http::build_client(Duration::from_secs(5)).expect("the client is built");
    let runtime = Arc::new(ProviderRuntime::new(
        client,
        daily_guard(1_000),
        Duration::from_secs(5),
        badbots::clock::system_clock(),
    ));
    let provider = AbuseIpdbProvider::new(
        ApiKey::new("test-key"),
        format!("{}/api/v2", server.uri()),
        30,
        runtime,
    );

    (server, provider)
}

#[tokio::test]
async fn a_strong_recent_report_convicts() {
    let (_server, provider) = provider_for("web_app_attack.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.provider, ProviderId::ABUSEIPDB);
    assert_eq!(provider.family(), SourceFamily::ABUSEIPDB);
    assert_eq!(provider.capability(), ProviderCapability::Primary);
    assert_eq!(verdict.evidence.len(), 1);

    let evidence = &verdict.evidence[0];
    assert_eq!(evidence.strength, EvidenceStrength::Convicting);
    assert_eq!(evidence.provider, ProviderId::ABUSEIPDB);
    assert_eq!(evidence.family, SourceFamily::ABUSEIPDB);
    assert_eq!(
        evidence
            .upstream_values
            .get("abuse_confidence_score")
            .unwrap(),
        "100"
    );
    assert_eq!(
        evidence.upstream_values.get("num_distinct_users").unwrap(),
        "5"
    );
    assert_eq!(evidence.upstream_values.get("total_reports").unwrap(), "12");
    assert_eq!(evidence.upstream_values.get("categories").unwrap(), "21");
    assert_eq!(
        evidence.upstream_values.get("usage_type").unwrap(),
        "Data Center"
    );
    assert_eq!(evidence.upstream_values.get("country_code").unwrap(), "US");
    assert_eq!(
        evidence.upstream_values.get("isp").unwrap(),
        "Example Hosting"
    );
    assert_eq!(
        evidence.upstream_values.get("domain").unwrap(),
        "example-hosting.test"
    );
    assert_eq!(evidence.upstream_values.get("is_tor").unwrap(), "false");
    assert!(verdict.suppression.is_none());
}

#[tokio::test]
async fn a_low_score_is_only_a_suspect_signal() {
    let (_server, provider) = provider_for("low_score.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_single_reporter_is_only_a_suspect_signal() {
    let (_server, provider) = provider_for("single_user.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_moderate_score_with_several_reporters_is_a_suspect_signal() {
    let (_server, provider) = provider_for("single_user_low_score.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_port_scan_alone_produces_no_evidence() {
    let (_server, provider) = provider_for("port_scan_only.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert!(verdict.evidence.is_empty());
}

#[tokio::test]
async fn a_low_score_produces_no_evidence() {
    let (_server, provider) = provider_for("no_reports.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert!(verdict.evidence.is_empty());
}

#[tokio::test]
async fn an_old_report_does_not_convict() {
    let (_server, provider) = provider_for("old_report.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_whitelisted_address_is_suppressed() {
    let (_server, provider) = provider_for("whitelisted.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert!(verdict.evidence.is_empty());
    assert_eq!(verdict.suppression, Some(Suppression::Safe));
    assert_eq!(verdict.coverage, CoverageLevel::Definitive);
    assert!(verdict.expires_at.is_none());
}

#[tokio::test]
async fn an_absent_whitelist_flag_leaves_the_conviction_rule_unchanged() {
    let (_server, provider) = provider_for("absent_whitelist_flag.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Convicting);
    assert!(verdict.suppression.is_none());
    assert!(
        !verdict.evidence[0]
            .upstream_values
            .contains_key("is_whitelisted")
    );
}

#[tokio::test]
async fn a_null_whitelist_flag_leaves_the_conviction_rule_unchanged() {
    let (_server, provider) = provider_for("null_whitelist_flag.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Convicting);
    assert!(verdict.suppression.is_none());
}

#[tokio::test]
async fn a_malformed_body_is_a_parse_error() {
    let (_server, provider) = provider_for("malformed.json").await;
    let error = provider.lookup(ip()).await.expect_err("the lookup fails");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn an_empty_body_is_a_parse_error() {
    let (_server, provider) = provider_for("empty.json").await;
    let error = provider.lookup(ip()).await.expect_err("the lookup fails");

    assert!(matches!(error, ProviderError::Parse(_)));
}

#[tokio::test]
async fn an_unauthorized_answer_is_reported() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"errors\":[{\"detail\":\"invalid key\"}]}"),
        )
        .mount(&server)
        .await;

    let client = badbots::http::build_client(Duration::from_secs(5)).expect("the client is built");
    let runtime = Arc::new(ProviderRuntime::new(
        client,
        daily_guard(1_000),
        Duration::from_secs(5),
        badbots::clock::system_clock(),
    ));
    let provider = AbuseIpdbProvider::new(
        ApiKey::new("test-key"),
        format!("{}/api/v2", server.uri()),
        30,
        runtime,
    );

    let error = provider.lookup(ip()).await.expect_err("the lookup fails");
    assert_eq!(error, ProviderError::Unauthorized);
}

#[tokio::test]
async fn the_key_is_sent_in_the_header_and_never_in_the_query() {
    let (server, provider) = provider_for("web_app_attack.json").await;
    provider.lookup(ip()).await.expect("the lookup succeeds");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1);

    let request = &requests[0];
    assert_eq!(request.headers.get("Key").unwrap(), "test-key");
    assert_eq!(request.headers.get("accept").unwrap(), "application/json");

    let query = request.url.query().unwrap_or_default();
    assert!(query.contains("ipAddress=45.32.1.1"));
    assert!(query.contains("maxAgeInDays=30"));
    assert!(query.contains("verbose=true"));
    assert!(!query.contains("test-key"));
}
