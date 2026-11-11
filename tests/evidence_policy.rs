//! The evidence policies and the order of the providers.

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use badbots::provider::{
    FeedProvider, FeedSnapshot, LookupProvider, ProviderCapability, ProviderCost, ProviderFinding,
};
use badbots::{
    Assertion, BadBots, Classification, Config, CoverageLevel, Evidence, EvidencePolicy,
    EvidenceStrength, MatchScope, ProviderError, ProviderId, ProviderRuntime, SourceFamily,
    ThreatCategory, VerdictReason, daily_guard,
};
use common::TestClock;
use time::OffsetDateTime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

/// A lookup provider that states its own price.
struct PricedProvider {
    id: ProviderId,
    family: SourceFamily,
    capability: ProviderCapability,
    cost: ProviderCost,
    endpoint: String,
    /// Whether the provider reports an observation about the address.
    hits: bool,
    runtime: Arc<ProviderRuntime>,
}

#[async_trait]
impl LookupProvider for PricedProvider {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        self.family.clone()
    }

    fn capability(&self) -> ProviderCapability {
        self.capability
    }

    fn cost(&self) -> ProviderCost {
        self.cost
    }

    async fn lookup(&self, _ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        let now = self.runtime.clock().now();
        let request = self.runtime.client().get(&self.endpoint);
        let response = self.runtime.send(request, now).await?;
        let _body = self.runtime.read_body(response).await?;

        let evidence = if self.hits {
            vec![Evidence {
                provider: self.id.clone(),
                family: self.family.clone(),
                assertion: Assertion::Attack,
                category: ThreatCategory::WebAttack,
                upstream_category: None,
                strength: EvidenceStrength::Convicting,
                scope: MatchScope::Exact,
                observed_at: None,
                published_at: None,
                retrieved_at: None,
                expires_at: None,
                observation_window: None,
                count: None,
                upstream_values: BTreeMap::new(),
            }]
        } else {
            Vec::new()
        };

        Ok(ProviderFinding {
            provider: self.id.clone(),
            coverage: CoverageLevel::Definitive,
            evidence,
            suppression: None,
            expires_at: None,
        })
    }
}

/// A list provider that publishes one observation about the assessed address.
struct ListProvider {
    entries: Vec<Evidence>,
}

#[async_trait]
impl FeedProvider for ListProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("list")
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("list")
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        Duration::from_secs(60 * 60)
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        Ok(FeedSnapshot {
            provider: self.id(),
            family: self.family(),
            published_at: None,
            retrieved_at: now(),
            expires_at: None,
            attribution: String::new(),
            header_lines: Vec::new(),
            entries: self.entries.clone(),
        })
    }
}

/// The observation the list provider publishes.
fn list_entry() -> Evidence {
    let mut upstream_values = BTreeMap::new();
    upstream_values.insert("address".to_string(), ip().to_string());

    Evidence {
        provider: ProviderId::new("list"),
        family: SourceFamily::new("list"),
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
        upstream_values,
    }
}

/// A mock server that answers every price class.
async fn server() -> MockServer {
    let server = MockServer::start().await;
    for endpoint in ["/low", "/medium", "/high"] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
    }
    server
}

/// The paths of the requests the server received.
async fn paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("the requests are recorded")
        .iter()
        .map(|request| request.url.path().to_string())
        .collect()
}

/// Builds a provider that answers at the given endpoint.
fn priced(
    runtime: Arc<ProviderRuntime>,
    endpoint: String,
    id: &'static str,
    cost: ProviderCost,
    capability: ProviderCapability,
    hits: bool,
) -> PricedProvider {
    PricedProvider {
        id: ProviderId::new(id),
        family: SourceFamily::new(id),
        capability,
        cost,
        endpoint,
        hits,
        runtime,
    }
}

#[tokio::test]
async fn the_lenient_policy_stops_at_the_cheapest_provider_that_hits() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let medium = format!("{}/medium", server.uri());
    let high = format!("{}/high", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                high,
                "high",
                ProviderCost::High,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                medium,
                "medium",
                ProviderCost::Medium,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                true,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
    assert_eq!(
        paths(&server).await,
        vec!["/low".to_string()],
        "the providers after the hit were not asked"
    );
}

#[tokio::test]
async fn the_lenient_policy_consults_every_provider_when_none_hits() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let medium = format!("{}/medium", server.uri());
    let high = format!("{}/high", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                high,
                "high",
                ProviderCost::High,
                ProviderCapability::Primary,
                false,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                medium,
                "medium",
                ProviderCost::Medium,
                ProviderCapability::Primary,
                false,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                false,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
    assert_eq!(
        paths(&server).await,
        vec![
            "/low".to_string(),
            "/medium".to_string(),
            "/high".to_string()
        ],
        "the providers were not asked from the cheapest to the most expensive one"
    );
}

#[tokio::test]
async fn a_provider_without_observations_is_not_a_hit() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let medium = format!("{}/medium", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                medium,
                "medium",
                ProviderCost::Medium,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                false,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(
        paths(&server).await,
        vec!["/low".to_string(), "/medium".to_string()],
        "the consultation stopped at the provider that reported nothing"
    );
}

#[tokio::test]
async fn the_loaded_lists_are_consulted_before_the_lookup_providers() {
    let server = server().await;
    let low = format!("{}/low", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .feed_provider(daily_guard(100), |_runtime| ListProvider {
            entries: vec![list_entry()],
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                true,
            )
        })
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.coverage.definitive, vec![ProviderId::new("list")]);
    assert!(
        paths(&server).await.is_empty(),
        "the lookup provider was asked although the list already hit"
    );
}

#[tokio::test]
async fn the_strict_policy_asks_the_primary_provider_first() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let high = format!("{}/high", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                high,
                "high",
                ProviderCost::High,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                true,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(
        paths(&server).await,
        vec!["/high".to_string()],
        "the price of a provider does not decide the order of the strict policy"
    );
}

#[tokio::test]
async fn the_lenient_policy_asks_the_cheapest_provider_first() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let high = format!("{}/high", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                high,
                "high",
                ProviderCost::High,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                true,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(
        paths(&server).await,
        vec!["/low".to_string()],
        "the cheapest provider was asked first"
    );
}

#[tokio::test]
async fn the_assessment_reports_the_coverage_of_the_verification() {
    let server = server().await;
    let low = format!("{}/low", server.uri());
    let medium = format!("{}/medium", server.uri());

    let bots = BadBots::builder()
        .config(Config::default())
        .clock(Arc::new(TestClock::new(now())))
        .evidence_policy(EvidencePolicy::Lenient)
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                medium,
                "medium",
                ProviderCost::Medium,
                ProviderCapability::Primary,
                true,
            )
        })
        .lookup_provider(daily_guard(100), move |runtime| {
            priced(
                runtime,
                low,
                "low",
                ProviderCost::Low,
                ProviderCapability::Corroborating,
                true,
            )
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;
    let assessed = bots.assess_ip(ip());

    assert_eq!(assessed.classification, verdict.classification);
    assert_eq!(assessed.reason, verdict.reason);
    assert_eq!(assessed.coverage, verdict.coverage);
    assert_eq!(
        paths(&server).await,
        vec!["/low".to_string()],
        "the assessment did not ask the provider again"
    );
}
