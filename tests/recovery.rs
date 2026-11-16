//! The recovery of a document that the publisher did not deliver.

#![cfg(feature = "abuseipdb")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use badbots::http::ClientSet;
use badbots::{AbuseIpdbConfig, ApiKey, BadBots, Config, ProviderError, ProviderId};
use time::OffsetDateTime;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use common::{fixture, render};

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn ip() -> std::net::IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn other_ip() -> std::net::IpAddr {
    "45.32.1.2".parse().unwrap()
}

/// The document the publisher serves.
fn document() -> String {
    render(&fixture("abuseipdb/web_app_attack.json"), now())
}

/// The configuration that asks the AbuseIPDB provider for the address.
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

/// The clients the library reaches the upstream with.
///
/// Every client names itself in a header, so a test can tell which client
/// carried a request.
fn clients() -> ClientSet {
    ClientSet::new(client("normal"), client("ipv4"), client("ipv6"))
}

/// One client of the set.
fn client(name: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "x-client",
        reqwest::header::HeaderValue::from_str(name).expect("the name is a header value"),
    );

    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .default_headers(headers)
        .build()
        .expect("the client is built")
}

/// A server that refuses the first request and serves the document after it.
async fn serve_one_refusal() -> MockServer {
    let server = MockServer::start().await;
    let served = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .respond_with(move |_: &Request| {
            if served.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(203)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(b"no")
            } else {
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(document())
            }
        })
        .mount(&server)
        .await;

    server
}

/// A server that refuses every request.
async fn serve_refusals() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(203)
                .insert_header("content-type", "text/xml")
                .set_body_bytes(b"no"),
        )
        .mount(&server)
        .await;

    server
}

/// The client that carried a request.
fn client_of(request: &Request) -> String {
    request
        .headers
        .get("x-client")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("normal")
        .to_string()
}

/// The requests a server received.
async fn requests(server: &MockServer) -> Vec<Request> {
    server
        .received_requests()
        .await
        .expect("the requests are recorded")
}

#[tokio::test]
async fn a_refused_document_is_recovered_over_the_other_address_family() {
    let server = serve_one_refusal().await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .client_set(clients())
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert!(
        verdict
            .evidence
            .iter()
            .any(|evidence| evidence.provider == ProviderId::ABUSEIPDB),
        "the verdict carries the evidence of the provider: {verdict:?}"
    );
    assert_eq!(verdict.coverage.definitive, vec![ProviderId::ABUSEIPDB]);
    assert!(verdict.coverage.failed.is_empty());

    let requests = requests(&server).await;
    assert_eq!(requests.len(), 2, "the request was repeated once");
    assert_eq!(client_of(&requests[0]), "normal");
    assert_eq!(
        client_of(&requests[1]),
        "ipv6",
        "the request was repeated over the other address family"
    );
}

#[tokio::test]
async fn the_family_that_delivered_the_document_is_remembered_for_the_host() {
    let server = serve_one_refusal().await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .client_set(clients())
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    bots.verify_ip(other_ip()).await;

    let requests = requests(&server).await;
    assert_eq!(requests.len(), 3);
    assert_eq!(client_of(&requests[0]), "normal");
    assert_eq!(client_of(&requests[1]), "ipv6");
    assert_eq!(
        client_of(&requests[2]),
        "ipv6",
        "the next request to the host uses the family that delivered the document"
    );
}

#[tokio::test]
async fn two_refusals_end_in_a_failure() {
    let server = serve_refusals().await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .client_set(clients())
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(
        verdict.coverage.failed,
        vec![(ProviderId::ABUSEIPDB, ProviderError::Status { code: 203 })]
    );
    assert!(verdict.evidence.is_empty());

    let requests = requests(&server).await;
    assert_eq!(requests.len(), 2, "the request was repeated once");
}

#[tokio::test]
async fn a_document_of_another_type_is_a_parse_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html></html>"),
        )
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .client_set(clients())
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.coverage.failed.len(), 1);
    let (provider, error) = &verdict.coverage.failed[0];
    assert_eq!(*provider, ProviderId::ABUSEIPDB);
    assert!(
        matches!(error, ProviderError::Parse(_)),
        "the coarse error names no URL: {error}"
    );

    let requests = requests(&server).await;
    assert_eq!(requests.len(), 2, "the request was repeated once");
}

#[tokio::test]
async fn the_budget_of_the_provider_is_spent_once_per_lookup() {
    let server = serve_one_refusal().await;
    let bots = BadBots::builder()
        .config(config(&format!("{}/api/v2", server.uri())))
        .client_set(clients())
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;

    let status = bots
        .provider_status()
        .into_iter()
        .find(|status| status.provider == ProviderId::ABUSEIPDB)
        .expect("the provider is reported");

    assert_eq!(status.quota_used, Some(1));
}
