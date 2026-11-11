//! The registration of a provider by the host application.

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use badbots::provider::{
    FeedProvider, FeedSnapshot, LookupProvider, ProviderCapability, ProviderFinding,
};
use badbots::{
    Assertion, BadBots, Classification, Config, ConfigError, CoverageLevel, Evidence,
    EvidenceStrength, MatchScope, ProviderError, ProviderId, ProviderRuntime, ProviderStatus,
    QuotaGuard, QuotaWindow, SourceFamily, Suppression, ThreatCategory, VerdictReason, daily_guard,
};
use common::TestClock;
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A provider the host application registers with the library.
struct InternalProvider {
    runtime: Arc<ProviderRuntime>,
    id: ProviderId,
    family: SourceFamily,
    /// The identity the finding claims.
    claim: (ProviderId, SourceFamily),
    /// The endpoint the provider asks for its answer.
    endpoint: Option<String>,
}

/// A provider that reports the identity it is registered under.
fn internal(
    runtime: Arc<ProviderRuntime>,
    id: &'static str,
    family: &'static str,
) -> InternalProvider {
    InternalProvider {
        runtime,
        id: ProviderId::new(id),
        family: SourceFamily::new(family),
        claim: (ProviderId::new(id), SourceFamily::new(family)),
        endpoint: None,
    }
}

#[async_trait]
impl LookupProvider for InternalProvider {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        self.family.clone()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        if let Some(endpoint) = &self.endpoint {
            let now = self.runtime.clock().now();
            let request = self.runtime.client().get(format!("{endpoint}?ip={ip}"));
            let response = self.runtime.send(request, now).await?;
            let _body = self.runtime.read_body(response).await?;
        }

        let evidence = Evidence {
            provider: self.claim.0.clone(),
            family: self.claim.1.clone(),
            assertion: Assertion::Attack,
            category: ThreatCategory::WebAttack,
            upstream_category: None,
            strength: EvidenceStrength::Corroborating,
            scope: MatchScope::Exact,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            upstream_values: BTreeMap::new(),
        };

        Ok(ProviderFinding {
            provider: self.claim.0.clone(),
            coverage: CoverageLevel::Definitive,
            evidence: vec![evidence],
            suppression: None,
            expires_at: None,
        })
    }
}

/// A list provider the host application registers with the library.
struct InternalFeed {
    runtime: Arc<ProviderRuntime>,
    id: ProviderId,
    family: SourceFamily,
}

#[async_trait]
impl FeedProvider for InternalFeed {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        self.family.clone()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        Duration::from_secs(60 * 60)
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        Ok(FeedSnapshot {
            provider: self.id.clone(),
            family: self.family.clone(),
            published_at: None,
            retrieved_at: self.runtime.clock().now(),
            expires_at: None,
            attribution: String::new(),
            header_lines: Vec::new(),
            entries: Vec::new(),
        })
    }
}

/// The status of a provider.
fn status_of(bots: &BadBots, provider: ProviderId) -> ProviderStatus {
    bots.provider_status()
        .into_iter()
        .find(|status| status.provider == provider)
        .expect("the provider is reported")
}

#[tokio::test]
async fn a_registered_provider_contributes_its_evidence() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(500), move |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.endpoint = Some(endpoint.clone());
            provider
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(address("45.32.1.1")).await;

    assert_eq!(
        verdict.coverage.definitive,
        vec![ProviderId::new("internal")]
    );
    assert!(verdict.coverage.failed.is_empty());
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].provider, ProviderId::new("internal"));
    assert_eq!(verdict.evidence[0].family, SourceFamily::new("internal"));

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(
        requests.len(),
        1,
        "the provider asked through the runtime of the library"
    );
}

#[tokio::test]
async fn the_answer_of_a_registered_provider_is_cached_under_its_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(500), move |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.endpoint = Some(endpoint.clone());
            provider
        })
        .build()
        .expect("the library is built");

    bots.verify_ip(address("45.32.1.1")).await;
    bots.verify_ip(address("45.32.1.1")).await;

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 1, "the answer of the provider is reused");
}

#[tokio::test]
async fn the_runtime_of_a_registered_provider_spends_the_quota_of_the_registration() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(3), move |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.endpoint = Some(endpoint.clone());
            provider
        })
        .build()
        .expect("the library is built");

    bots.verify_ip(address("45.32.1.1")).await;

    let status = status_of(&bots, ProviderId::new("internal"));
    assert_eq!(status.quota_used, Some(1));
    assert_eq!(status.quota_limit, Some(3));
}

#[test]
fn two_providers_with_the_same_id_fail_the_build() {
    let error = BadBots::builder()
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "internal", "internal")
        })
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "internal", "internal")
        })
        .build()
        .expect_err("the build fails");

    assert!(matches!(error, ConfigError::Invalid(_)));
    assert!(
        error.to_string().contains("internal"),
        "the message names the id: {error}"
    );
}

#[cfg(feature = "abuseipdb")]
#[test]
fn a_registered_provider_may_not_reuse_the_id_of_a_built_in_provider() {
    use badbots::{AbuseIpdbConfig, ApiKey};

    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("test-key")),
        daily_quota: None,
        base_url: None,
        max_age_days: None,
    });

    let error = BadBots::builder()
        .config(config)
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "abuseipdb", "abuseipdb")
        })
        .build()
        .expect_err("the build fails");

    assert!(
        error.to_string().contains("abuseipdb"),
        "the message names the id: {error}"
    );
}

#[tokio::test]
async fn the_engine_stamps_the_identity_of_the_registering_provider() {
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(10), |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.claim = (ProviderId::new("other"), SourceFamily::new("other"));
            provider
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(address("45.32.1.1")).await;

    assert_eq!(verdict.evidence[0].provider, ProviderId::new("internal"));
    assert_eq!(verdict.evidence[0].family, SourceFamily::new("internal"));
    assert_eq!(
        verdict.coverage.definitive,
        vec![ProviderId::new("internal")]
    );
}

#[tokio::test]
async fn a_lookup_and_a_list_of_the_same_id_spend_their_own_quota() {
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(11), |runtime| {
            internal(runtime, "shared", "shared")
        })
        .feed_provider(daily_guard(22), |runtime| InternalFeed {
            runtime,
            id: ProviderId::new("shared"),
            family: SourceFamily::new("shared"),
        })
        .build()
        .expect("the library is built");

    let limits: Vec<Option<u32>> = bots
        .provider_status()
        .into_iter()
        .filter(|status| status.provider == ProviderId::new("shared"))
        .map(|status| status.quota_limit)
        .collect();

    assert_eq!(limits.len(), 2, "both providers are reported");
    assert!(
        limits.contains(&Some(11)),
        "the lookup spends its own quota"
    );
    assert!(limits.contains(&Some(22)), "the list spends its own quota");
}

#[test]
fn a_finding_can_be_serialized_and_read_back() {
    let finding = ProviderFinding {
        provider: ProviderId::new("internal"),
        coverage: CoverageLevel::Definitive,
        evidence: vec![Evidence {
            provider: ProviderId::new("internal"),
            family: SourceFamily::new("internal"),
            assertion: Assertion::Attack,
            category: ThreatCategory::WebAttack,
            upstream_category: None,
            strength: EvidenceStrength::Corroborating,
            scope: MatchScope::Exact,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            upstream_values: BTreeMap::new(),
        }],
        suppression: Some(Suppression::Benign),
        expires_at: Some(now()),
    };

    let json = serde_json::to_string(&finding).expect("the finding is serialized");
    let read: ProviderFinding = serde_json::from_str(&json).expect("the finding is read back");

    assert_eq!(finding, read);
}

#[test]
fn a_registered_provider_appears_in_the_status() {
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(500), |runtime| {
            internal(runtime, "internal", "internal")
        })
        .build()
        .expect("the library is built");

    let status = status_of(&bots, ProviderId::new("internal"));
    assert!(status.enabled);
    assert_eq!(status.family, SourceFamily::new("internal"));
    assert_eq!(status.capability, ProviderCapability::Corroborating);
    assert_eq!(status.quota_used, Some(0));
    assert_eq!(status.quota_limit, Some(500));
    assert!(status.last_attempt.is_none());
    assert!(status.last_success.is_none());
}

#[tokio::test]
async fn two_providers_of_one_family_count_as_one_vote() {
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "first", "shared")
        })
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "second", "shared")
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(address("45.32.1.1")).await;

    assert_eq!(verdict.evidence.len(), 2);
    assert_eq!(verdict.classification, Classification::Suspect);
    assert_eq!(verdict.reason, VerdictReason::EvidencePresent);
}

#[tokio::test]
async fn two_providers_of_two_families_corroborate() {
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "first", "first")
        })
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "second", "second")
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(address("45.32.1.1")).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
}

#[tokio::test]
async fn the_quota_of_a_registered_provider_is_exhausted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(1), move |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.endpoint = Some(endpoint.clone());
            provider
        })
        .lookup_provider(daily_guard(10), |runtime| {
            internal(runtime, "other", "other")
        })
        .build()
        .expect("the library is built");

    let first = bots.verify_ip(address("45.32.1.1")).await;
    assert!(first.coverage.failed.is_empty());

    let second = bots.verify_ip(address("45.32.1.2")).await;
    assert_eq!(
        second.coverage.failed,
        vec![(ProviderId::new("internal"), ProviderError::QuotaExhausted)]
    );
    assert!(
        second
            .evidence
            .iter()
            .any(|evidence| evidence.provider == ProviderId::new("other")),
        "the evidence of the other provider is unaffected"
    );
}

#[tokio::test]
async fn an_unlimited_quota_never_refuses_a_registered_provider() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(QuotaGuard::unlimited(), move |runtime| {
            let mut provider = internal(runtime, "internal", "internal");
            provider.endpoint = Some(endpoint.clone());
            provider
        })
        .build()
        .expect("the library is built");

    for index in 1..=5u8 {
        let verdict = bots.verify_ip(address(&format!("45.32.1.{index}"))).await;
        assert!(verdict.coverage.failed.is_empty());
    }

    let status = status_of(&bots, ProviderId::new("internal"));
    assert_eq!(status.quota_used, Some(5));
    assert_eq!(status.quota_limit, None);
}

#[test]
fn a_provider_is_built_with_the_quota_guard_of_the_crate_root() {
    let quota = QuotaGuard::new(10, QuotaWindow::Day);
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(quota, |runtime| internal(runtime, "internal", "internal"))
        .build()
        .expect("the library is built");

    let status = status_of(&bots, ProviderId::new("internal"));
    assert_eq!(status.quota_limit, Some(10));
}
