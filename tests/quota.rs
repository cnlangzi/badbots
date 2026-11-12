//! The budget a host injects for a provider.

mod common;

use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use badbots::provider::{LookupProvider, ProviderCapability, ProviderCost, ProviderFinding};
use badbots::{
    BadBots, CoverageLevel, ProviderError, ProviderId, ProviderRuntime, SourceFamily, daily_guard,
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

/// A provider that spends the budget of the runtime it performs its request in.
struct Internal {
    runtime: Arc<ProviderRuntime>,
    id: ProviderId,
    family: SourceFamily,
    endpoint: String,
}

#[async_trait]
impl LookupProvider for Internal {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        self.family.clone()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn cost(&self) -> ProviderCost {
        ProviderCost::Medium
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        let now = self.runtime.clock().now();
        let request = self
            .runtime
            .client()
            .get(format!("{}?ip={ip}", self.endpoint));
        let response = self.runtime.send(request, now).await?;
        let _body = self.runtime.read_body(response).await?;
        Ok(ProviderFinding::empty(self.id(), CoverageLevel::Partial))
    }
}

#[tokio::test]
async fn two_providers_that_share_one_budget_spend_it_together() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/intel"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    let endpoint = format!("{}/intel", server.uri());

    let budget = daily_guard(1);
    let first = endpoint.clone();
    let bots = BadBots::builder()
        .clock(Arc::new(TestClock::new(now())))
        .lookup_provider(Arc::clone(&budget), move |runtime| Internal {
            runtime,
            id: ProviderId::new("first"),
            family: SourceFamily::new("first"),
            endpoint: first.clone(),
        })
        .lookup_provider(Arc::clone(&budget), move |runtime| Internal {
            runtime,
            id: ProviderId::new("second"),
            family: SourceFamily::new("second"),
            endpoint: endpoint.clone(),
        })
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(address("45.32.1.1")).await;

    assert_eq!(budget.used(now()), 1, "the shared budget is spent once");
    assert_eq!(verdict.coverage.failed.len(), 1);
    let (provider, error) = &verdict.coverage.failed[0];
    assert_eq!(error, &ProviderError::QuotaExhausted);
    assert!(
        *provider == ProviderId::new("first") || *provider == ProviderId::new("second"),
        "the refused provider is one of the two: {provider}"
    );
}

#[cfg(feature = "abuseipdb")]
#[tokio::test]
async fn an_injected_budget_replaces_the_configured_budget() {
    use badbots::{AbuseIpdbConfig, ApiKey, Config, ProviderConfig};
    use common::{fixture, render};

    let server = MockServer::start().await;
    let body = render(
        &fixture("abuseipdb/no_reports.json"),
        OffsetDateTime::now_utc(),
    );
    Mock::given(method("GET"))
        .and(path("/api/v2/check"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let config = Config {
        providers: ProviderConfig {
            abuseipdb: Some(AbuseIpdbConfig {
                enabled: true,
                api_key: Some(ApiKey::new("test-key")),
                daily_quota: Some(1),
                base_url: Some(format!("{}/api/v2", server.uri())),
                max_age_days: None,
            }),
            ..ProviderConfig::default()
        },
        ..Config::default()
    };

    let bots = BadBots::builder()
        .config(config)
        .quota(ProviderId::ABUSEIPDB, daily_guard(5))
        .build()
        .expect("the library is built");

    bots.verify_ip(address("45.32.1.1")).await;

    let status = bots
        .provider_status()
        .into_iter()
        .find(|status| status.provider == ProviderId::ABUSEIPDB)
        .expect("the provider is reported");
    assert_eq!(status.quota_limit, Some(5), "the injected budget is spent");
    assert_eq!(status.quota_used, Some(1));
}

#[test]
fn a_budget_that_no_provider_spends_is_reported() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder(Arc::clone(&recorded));

    tracing::subscriber::with_default(recorder, || {
        BadBots::builder()
            .quota(ProviderId::new("unknown"), daily_guard(5))
            .build()
            .expect("the library is built");
    });

    let recorded = recorded.lock().expect("the lock is held");
    assert_eq!(recorded.as_slice(), ["unknown"]);
}

/// A subscriber that records the provider of every event.
struct Recorder(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for Recorder {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = Visitor(self.0.lock().expect("the lock is held"));
        event.record(&mut visitor);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// A visitor that records the provider of an event.
struct Visitor<'a>(MutexGuard<'a, Vec<String>>);

impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "provider" {
            self.0.push(format!("{value:?}"));
        }
    }
}
