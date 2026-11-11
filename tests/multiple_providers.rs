//! The behaviour of the library with more than one provider.

#![cfg(all(feature = "abuseipdb", feature = "crowdsec"))]

mod common;

use std::net::IpAddr;

use badbots::{
    AbuseIpdbConfig, ApiKey, BadBots, Classification, Config, CrowdSecConfig, ProviderError,
    ProviderId, VerdictReason,
};
use common::{fixture, render};
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn config(abuseipdb_url: &str, crowdsec_url: &str) -> Config {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("abuse-key")),
        daily_quota: None,
        base_url: Some(abuseipdb_url.to_string()),
        max_age_days: None,
    });
    config.providers.crowdsec = Some(CrowdSecConfig {
        enabled: true,
        api_key: Some(ApiKey::new("crowdsec-key")),
        monthly_quota: None,
        base_url: Some(crowdsec_url.to_string()),
        behavior_intents: None,
    });
    config
}

#[tokio::test]
async fn a_failing_provider_does_not_discard_the_evidence_of_the_other() {
    let abuseipdb = MockServer::start().await;
    let body = render(
        &fixture("abuseipdb/no_reports.json"),
        OffsetDateTime::now_utc(),
    );
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&abuseipdb)
        .await;

    let crowdsec = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/smoke/45.32.1.1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&crowdsec)
        .await;

    let bots = BadBots::builder()
        .config(config(
            &format!("{}/api/v2", abuseipdb.uri()),
            &format!("{}/v2", crowdsec.uri()),
        ))
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
    assert_eq!(verdict.coverage.definitive, vec![ProviderId::ABUSEIPDB]);
    assert_eq!(verdict.coverage.failed.len(), 1);
    assert_eq!(verdict.coverage.failed[0].0, ProviderId::CROWDSEC);
    assert_eq!(
        verdict.coverage.failed[0].1,
        ProviderError::Status { code: 500 }
    );

    let assessed = bots.assess_ip(ip());
    assert_eq!(assessed.coverage.failed.len(), 1);
    assert_eq!(assessed.coverage.failed[0].0, ProviderId::CROWDSEC);
}

#[tokio::test]
async fn a_conviction_stops_the_sequence_of_providers() {
    let abuseipdb = MockServer::start().await;
    let body = render(
        &fixture("abuseipdb/web_app_attack.json"),
        OffsetDateTime::now_utc(),
    );
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&abuseipdb)
        .await;

    let crowdsec = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/smoke/45.32.1.1"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&crowdsec)
        .await;

    let bots = BadBots::builder()
        .config(config(
            &format!("{}/api/v2", abuseipdb.uri()),
            &format!("{}/v2", crowdsec.uri()),
        ))
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
    assert_eq!(verdict.coverage.definitive, vec![ProviderId::ABUSEIPDB]);
    assert!(
        crowdsec
            .received_requests()
            .await
            .expect("the requests are recorded")
            .is_empty(),
        "the second provider was asked although the address was convicted"
    );
}
