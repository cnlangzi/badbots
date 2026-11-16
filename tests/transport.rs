//! The transport the library builds and owns.

#![cfg(feature = "abuseipdb")]

mod common;

use std::net::IpAddr;

use badbots::{AbuseIpdbConfig, ApiKey, BadBots, Classification, Config, ConfigError, ProviderId};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{fixture, render};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
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

/// A server that answers every request with the document of the publisher.
async fn serve() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(render(
                    &fixture("abuseipdb/web_app_attack.json"),
                    time::OffsetDateTime::now_utc(),
                )),
        )
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn a_library_that_builds_its_own_clients_reaches_the_upstream() {
    let server = serve().await;
    let config = Config {
        proxy: Some(server.uri()),
        ..config(&format!("{}/api/v2", server.uri()))
    };

    let bots = BadBots::builder()
        .config(config)
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert!(
        !server
            .received_requests()
            .await
            .expect("the requests are recorded")
            .is_empty(),
        "the request reached the proxy of the configuration"
    );
}

#[test]
fn a_library_that_is_built_with_a_root_certificate_is_built() {
    let config = Config {
        client_ca_pem: Some(fixture("client/root.pem")),
        ..Default::default()
    };

    BadBots::builder()
        .config(config)
        .build()
        .expect("the library is built");
}

#[test]
fn a_root_certificate_that_cannot_be_read_is_reported() {
    let config = Config {
        client_ca_pem: Some("not a certificate".to_string()),
        ..Default::default()
    };

    let error = BadBots::builder()
        .config(config)
        .build()
        .expect_err("the certificate is rejected");

    assert!(
        matches!(error, ConfigError::Invalid(_)),
        "the error names the configuration: {error}"
    );
}

#[test]
fn a_proxy_that_cannot_be_read_is_reported() {
    let config = Config {
        proxy: Some("not a proxy".to_string()),
        ..Default::default()
    };

    let error = BadBots::builder()
        .config(config)
        .build()
        .expect_err("the proxy is rejected");

    assert!(
        matches!(error, ConfigError::Invalid(_)),
        "the error names the configuration: {error}"
    );
}

#[test]
fn the_provider_the_library_built_is_reported() {
    let bots = BadBots::builder()
        .config(Config::default())
        .build()
        .expect("the library is built");

    assert!(
        bots.provider_status()
            .iter()
            .all(|status| status.provider != ProviderId::ABUSEIPDB),
        "no provider is enabled"
    );
}
