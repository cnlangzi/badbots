//! The CrowdSec CTI adapter against checked-in fixtures.

#![cfg(feature = "crowdsec")]

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use badbots::provider::crowdsec::CrowdSecProvider;
use badbots::provider::lookup::ProviderRuntime;
use badbots::provider::{LookupProvider, ProviderCapability};
use badbots::{
    ApiKey, EvidenceStrength, ProviderError, ProviderId, SourceFamily, Suppression, monthly_guard,
};
use common::{fixture, render};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

async fn provider_for(name: &str) -> (MockServer, CrowdSecProvider) {
    let server = MockServer::start().await;
    let body = render(
        &fixture(&format!("crowdsec/{name}")),
        OffsetDateTime::now_utc(),
    );
    Mock::given(method("GET"))
        .and(path("/v2/smoke/45.32.1.1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let client = badbots::http::build_client(Duration::from_secs(5)).expect("the client is built");
    let runtime = Arc::new(ProviderRuntime::new(
        client,
        monthly_guard(120),
        Duration::from_secs(5),
        badbots::clock::system_clock(),
    ));
    let provider = CrowdSecProvider::new(
        ApiKey::new("test-key"),
        format!("{}/v2", server.uri()),
        BTreeMap::new(),
        runtime,
    );

    (server, provider)
}

#[tokio::test]
async fn a_malicious_behavior_convicts() {
    let (_server, provider) = provider_for("malicious_exploit.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.provider, ProviderId::CROWDSEC);
    assert_eq!(provider.family(), SourceFamily::CROWDSEC);
    assert_eq!(provider.capability(), ProviderCapability::Primary);
    assert_eq!(verdict.evidence.len(), 1);

    let evidence = &verdict.evidence[0];
    assert_eq!(evidence.strength, EvidenceStrength::Convicting);
    assert_eq!(
        evidence.upstream_values.get("reputation").unwrap(),
        "malicious"
    );
    assert_eq!(
        evidence.upstream_values.get("background_noise").unwrap(),
        "medium"
    );
    assert_eq!(
        evidence.upstream_values.get("behaviors").unwrap(),
        "http:exploit"
    );
    assert!(verdict.suppression.is_none());
}

#[tokio::test]
async fn a_high_background_noise_only_produces_an_indicative_observation() {
    let (_server, provider) = provider_for("background_noise_high.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_suspicious_reputation_only_produces_an_indicative_observation() {
    let (_server, provider) = provider_for("suspicious_scan.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_malicious_reputation_without_a_malicious_behavior_only_produces_an_indicative_observation()
 {
    let (_server, provider) = provider_for("malicious_generic_scan.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
}

#[tokio::test]
async fn a_false_positive_tag_suppresses_the_address() {
    let (_server, provider) = provider_for("false_positive.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Indicative);
    assert_eq!(verdict.suppression, Some(Suppression::Safe));
    assert_eq!(
        verdict.evidence[0]
            .upstream_values
            .get("false_positives")
            .unwrap(),
        "cdn:cloudflare_exit_node"
    );
}

#[tokio::test]
async fn a_benign_reputation_suppresses_the_address() {
    let (_server, provider) = provider_for("benign.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert!(verdict.evidence.is_empty());
    assert_eq!(verdict.suppression, Some(Suppression::Benign));
}

#[tokio::test]
async fn a_community_blocklist_classification_convicts() {
    let (_server, provider) = provider_for("community_blocklist.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Convicting);
    assert_eq!(
        verdict.evidence[0]
            .upstream_values
            .get("classifications")
            .unwrap(),
        "community-blocklist"
    );
}

#[tokio::test]
async fn an_intelligence_blocklist_reference_convicts() {
    let (_server, provider) = provider_for("intelligence_blocklist.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].strength, EvidenceStrength::Convicting);
    assert_eq!(
        verdict.evidence[0]
            .upstream_values
            .get("references")
            .unwrap(),
        "list:crowdsec_intelligence_blocklist"
    );
}

#[tokio::test]
async fn an_unknown_reputation_produces_no_evidence() {
    let (_server, provider) = provider_for("unknown.json").await;
    let verdict = provider.lookup(ip()).await.expect("the lookup succeeds");

    assert!(verdict.evidence.is_empty());
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
async fn the_key_is_sent_in_the_header() {
    let (server, provider) = provider_for("malicious_exploit.json").await;
    provider.lookup(ip()).await.expect("the lookup succeeds");

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers.get("x-api-key").unwrap(), "test-key");
}
