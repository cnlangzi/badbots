//! The events the library reports.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use badbots::provider::{
    FeedProvider, FeedSnapshot, LookupProvider, ProviderCapability, ProviderCost, ProviderFinding,
};
use badbots::{
    Assertion, BadBots, Config, CoverageLevel, Evidence, EvidenceStrength, MatchScope,
    ProviderError, ProviderId, SourceFamily, ThreatCategory, daily_guard,
};
use time::{OffsetDateTime, macros::datetime};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A provider that answers with the outcome the test asks for.
struct ScriptedProvider {
    id: ProviderId,
    failure: Option<ProviderError>,
}

#[async_trait]
impl LookupProvider for ScriptedProvider {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("scripted")
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Primary
    }

    fn cost(&self) -> ProviderCost {
        ProviderCost::Medium
    }

    async fn lookup(&self, _ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(ProviderFinding::empty(self.id(), CoverageLevel::Partial)),
        }
    }
}

/// A list provider that answers with the outcome the test asks for.
struct ScriptedList {
    id: ProviderId,
    answer: Result<FeedSnapshot, ProviderError>,
    min_refresh_interval: Duration,
}

#[async_trait]
impl FeedProvider for ScriptedList {
    fn id(&self) -> ProviderId {
        self.id.clone()
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("scripted")
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        self.answer.clone()
    }
}

/// One observation of a scripted snapshot.
fn observation(provider: &ProviderId, address: &str) -> Evidence {
    let mut upstream_values = BTreeMap::new();
    upstream_values.insert("address".to_string(), address.to_string());

    Evidence {
        provider: provider.clone(),
        family: SourceFamily::new("scripted"),
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

/// A snapshot that holds two observations.
fn snapshot(provider: &ProviderId) -> FeedSnapshot {
    FeedSnapshot {
        provider: provider.clone(),
        family: SourceFamily::new("scripted"),
        published_at: None,
        retrieved_at: now(),
        expires_at: None,
        attribution: String::new(),
        header_lines: Vec::new(),
        entries: vec![
            observation(provider, "45.32.1.1"),
            observation(provider, "45.32.1.2"),
        ],
    }
}

/// A library that asks the given provider about an address.
fn bots_with(provider: ProviderId) -> BadBots {
    BadBots::builder()
        .config(Config::default())
        .lookup_provider(daily_guard(100), move |_runtime| ScriptedProvider {
            id: provider,
            failure: None,
        })
        .build()
        .expect("the library is built")
}

/// A library whose provider fails to answer.
fn bots_with_failing_provider(provider: ProviderId) -> BadBots {
    BadBots::builder()
        .config(Config::default())
        .lookup_provider(daily_guard(100), move |_runtime| ScriptedProvider {
            id: provider,
            failure: Some(ProviderError::Timeout),
        })
        .build()
        .expect("the library is built")
}

/// A library that refreshes the given list.
fn bots_with_list(list: ScriptedList) -> BadBots {
    BadBots::builder()
        .config(Config::default())
        .feed_provider(daily_guard(100), move |_runtime| Arc::new(list))
        .build()
        .expect("the library is built")
}

#[tokio::test]
async fn a_queued_verification_is_reported() {
    subscribe();
    let bots = bots_with(ProviderId::new("queued"));

    bots.verify_ip(address("45.32.1.1")).await;

    let event = event(
        "a verification of the address was queued",
        "ip",
        "45.32.1.1",
    )
    .expect("the queued verification is reported");
    assert_eq!(event.level, tracing::Level::DEBUG);
}

#[tokio::test]
async fn a_provider_that_answers_is_reported() {
    subscribe();
    let provider = ProviderId::new("answered");
    let bots = bots_with(provider.clone());

    bots.verify_ip(address("45.32.2.2")).await;

    let event = event("the provider answered about the address", "ip", "45.32.2.2")
        .expect("the answer of the provider is reported");
    assert_eq!(event.level, tracing::Level::DEBUG);
    assert_eq!(event.field("provider"), Some(provider.as_str()));
}

#[tokio::test]
async fn a_provider_that_fails_is_reported() {
    subscribe();
    let provider = ProviderId::new("failed");
    let bots = bots_with_failing_provider(provider.clone());

    bots.verify_ip(address("45.32.3.3")).await;

    let event = event(
        "the provider did not answer about the address",
        "ip",
        "45.32.3.3",
    )
    .expect("the failure of the provider is reported");
    assert_eq!(event.level, tracing::Level::WARN);
    assert_eq!(event.field("provider"), Some(provider.as_str()));
    assert_eq!(event.field("error"), Some("provider request timed out"));
}

#[tokio::test]
async fn a_finished_verification_is_reported() {
    subscribe();
    let bots = bots_with(ProviderId::new("finished"));

    let verdict = bots.verify_ip(address("45.32.4.4")).await;

    let event = event(
        "the verification of the address finished",
        "ip",
        "45.32.4.4",
    )
    .expect("the finished verification is reported");
    assert_eq!(event.level, tracing::Level::INFO);
    assert_eq!(
        event.field("classification"),
        Some(format!("{:?}", verdict.classification).as_str())
    );
    assert_eq!(
        event.field("reason"),
        Some(format!("{:?}", verdict.reason).as_str())
    );
}

#[tokio::test]
async fn a_refreshed_list_is_reported() {
    subscribe();
    let provider = ProviderId::new("refreshed");
    let bots = bots_with_list(ScriptedList {
        id: provider.clone(),
        answer: Ok(snapshot(&provider)),
        min_refresh_interval: Duration::ZERO,
    });

    bots.refresh_feeds().await;

    let event = event("the list was refreshed", "provider", provider.as_str())
        .expect("the refreshed list is reported");
    assert_eq!(event.level, tracing::Level::INFO);
    assert_eq!(event.field("entries"), Some("2"));
}

#[tokio::test]
async fn a_list_that_cannot_be_refreshed_is_reported() {
    subscribe();
    let provider = ProviderId::new("unrefreshed");
    let bots = bots_with_list(ScriptedList {
        id: provider.clone(),
        answer: Err(ProviderError::Status { code: 500 }),
        min_refresh_interval: Duration::ZERO,
    });

    bots.refresh_feeds().await;

    let event = event(
        "the list could not be refreshed",
        "provider",
        provider.as_str(),
    )
    .expect("the failed refresh is reported");
    assert_eq!(event.level, tracing::Level::WARN);
    assert_eq!(event.field("error"), Some("provider returned status 500"));
}

#[tokio::test]
async fn a_list_that_is_refreshed_too_early_is_reported() {
    subscribe();
    let provider = ProviderId::new("early");
    let bots = bots_with_list(ScriptedList {
        id: provider.clone(),
        answer: Ok(snapshot(&provider)),
        min_refresh_interval: Duration::from_secs(60 * 60),
    });

    bots.refresh_feeds().await;
    bots.refresh_feeds().await;

    let event = event(
        "the list was not refreshed because its interval has not elapsed",
        "provider",
        provider.as_str(),
    )
    .expect("the skipped refresh is reported");
    assert_eq!(event.level, tracing::Level::DEBUG);
    let remaining = event
        .field("remaining")
        .expect("the time that is left is reported");
    assert!(
        seconds(remaining) > 0.0,
        "the time that is left is reported: {remaining}"
    );
}

/// An event the library reported.
#[derive(Clone, Debug)]
struct Event {
    level: tracing::Level,
    message: String,
    fields: Vec<(String, String)>,
}

impl Event {
    /// The value of one of the fields of the event.
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The events the library reported.
static EVENTS: OnceLock<Arc<Mutex<Vec<Event>>>> = OnceLock::new();

/// Installs the subscriber that records the events of the library.
///
/// The subscriber is global, so that the events of the worker thread are
/// recorded as well.
fn subscribe() {
    EVENTS.get_or_init(|| {
        let events = Arc::new(Mutex::new(Vec::new()));
        let _ = tracing::subscriber::set_global_default(Subscriber(Arc::clone(&events)));
        events
    });
}

/// The event with the given message that carries the given value.
fn event(message: &str, field: &str, value: &str) -> Option<Event> {
    let recorded = EVENTS
        .get()
        .expect("the subscriber is installed")
        .lock()
        .expect("the lock is held");
    recorded
        .iter()
        .find(|event| event.message == message && event.field(field) == Some(value))
        .cloned()
}

/// The number of seconds a duration field carries.
fn seconds(field: &str) -> f64 {
    field
        .trim_end_matches(|character: char| !character.is_ascii_digit() && character != '.')
        .parse()
        .unwrap_or_default()
}

/// A subscriber that records every event the library reports.
struct Subscriber(Arc<Mutex<Vec<Event>>>);

impl tracing::Subscriber for Subscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = Visitor { fields: Vec::new() };
        event.record(&mut visitor);
        let message = visitor
            .fields
            .iter()
            .find(|(field, _)| field == "message")
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let mut recorded = self.0.lock().expect("the lock is held");
        recorded.push(Event {
            level: *event.metadata().level(),
            message,
            fields: visitor
                .fields
                .into_iter()
                .filter(|(field, _)| field != "message")
                .collect(),
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// A visitor that records the fields of an event.
struct Visitor {
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.fields
            .push((field.name().to_string(), format!("{value:?}")));
    }
}
