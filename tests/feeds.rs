//! The feed machinery of the library.

#![cfg(all(feature = "spamhaus", feature = "dshield", feature = "blocklist_de"))]

mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use badbots::model::{Evidence, EvidenceStrength};
use badbots::provider::{FeedProvider, FeedSnapshot, ProviderCapability, ProviderStatus};
use badbots::{
    BadBots, BlocklistDeConfig, Classification, Config, DShieldConfig, MatchScope, ProviderError,
    ProviderId, SourceFamily, SpamhausConfig, VerdictReason,
};
use common::{TestClock, fixture};
use time::{OffsetDateTime, macros::datetime};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn now() -> OffsetDateTime {
    datetime!(2025-01-01 12:00:00 UTC)
}

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A list provider that answers with the snapshots the test asks for.
struct ScriptedProvider {
    snapshots: Vec<Result<FeedSnapshot, ProviderError>>,
    min_refresh_interval: Duration,
    calls: AtomicUsize,
}

impl ScriptedProvider {
    fn new(snapshots: Vec<Result<FeedSnapshot, ProviderError>>) -> Arc<Self> {
        Self::with_interval(snapshots, Duration::ZERO)
    }

    fn with_interval(
        snapshots: Vec<Result<FeedSnapshot, ProviderError>>,
        min_refresh_interval: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshots,
            min_refresh_interval,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl FeedProvider for ScriptedProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("scripted")
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
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let snapshot = self
            .snapshots
            .get(index % self.snapshots.len())
            .expect("the provider has a snapshot");

        match snapshot {
            Ok(snapshot) => Ok(snapshot.clone()),
            Err(error) => Err(error.clone()),
        }
    }
}

/// One observation of a scripted snapshot.
fn observation(address: &str, generation: &str) -> Evidence {
    let mut upstream_values = BTreeMap::new();
    upstream_values.insert("address".to_string(), address.to_string());
    upstream_values.insert("generation".to_string(), generation.to_string());

    Evidence {
        provider: ProviderId::new("scripted"),
        family: SourceFamily::new("scripted"),
        assertion: badbots::Assertion::Attack,
        category: badbots::ThreatCategory::WebAttack,
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

/// A snapshot that holds the observations of one generation.
fn snapshot(generation: &str) -> FeedSnapshot {
    FeedSnapshot {
        provider: ProviderId::new("scripted"),
        family: SourceFamily::new("scripted"),
        published_at: None,
        retrieved_at: now(),
        expires_at: None,
        attribution: String::new(),
        header_lines: Vec::new(),
        entries: vec![
            observation("45.32.1.1", generation),
            observation("45.32.1.2", generation),
        ],
    }
}

#[tokio::test]
async fn a_loaded_list_answers_the_assessment_without_network_io() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config_for_spamhaus(&server.uri()))
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;
    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 2);

    let verdict = bots.assess_ip(address("1.10.16.5"));
    assert_eq!(verdict.classification, Classification::Suspect);
    assert_eq!(verdict.reason, VerdictReason::EvidencePresent);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].family, SourceFamily::SPAMHAUS);

    let requests = server
        .received_requests()
        .await
        .expect("the requests are recorded");
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn a_list_that_cannot_be_read_keeps_the_previous_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let clock = TestClock::new(now());
    let bots = BadBots::builder()
        .config(config_for_spamhaus(&server.uri()))
        .clock(Arc::new(clock.clone()))
        .build()
        .expect("the library is built");

    let report = bots.refresh_feeds().await;
    assert!(report.results.iter().all(|result| result.result.is_ok()));

    clock.advance(Duration::from_secs(60 * 60));
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("spamhaus/malformed.json")),
        )
        .mount(&server)
        .await;

    let report = bots.refresh_feeds().await;
    let failure = report
        .results
        .iter()
        .find(|result| result.provider == ProviderId::SPAMHAUS)
        .expect("the provider is reported");
    assert!(matches!(failure.result, Err(ProviderError::Parse(_))));

    let verdict = bots.assess_ip(address("1.10.16.5"));
    assert_eq!(verdict.classification, Classification::Suspect);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].family, SourceFamily::SPAMHAUS);
}

#[tokio::test]
async fn a_refresh_inside_the_minimum_interval_is_skipped() {
    let provider =
        ScriptedProvider::with_interval(vec![Ok(snapshot("a"))], Duration::from_secs(60 * 60));
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;
    assert_eq!(provider.calls(), 1);

    let report = bots.refresh_feeds().await;
    assert_eq!(provider.calls(), 1);
    let result = &report.results[0];
    assert!(matches!(
        result.result,
        Err(ProviderError::RateLimited {
            retry_after: Some(_)
        })
    ));
}

#[tokio::test]
async fn the_interval_applies_to_a_failed_refresh_as_well() {
    let provider = ScriptedProvider::with_interval(
        vec![Err(ProviderError::Status { code: 500 })],
        Duration::from_secs(60 * 60),
    );
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    let report = bots.refresh_feeds().await;
    assert!(matches!(
        report.results[0].result,
        Err(ProviderError::Status { code: 500 })
    ));
    assert_eq!(provider.calls(), 1);

    let report = bots.refresh_feeds().await;
    assert_eq!(provider.calls(), 1);
    assert!(matches!(
        report.results[0].result,
        Err(ProviderError::RateLimited { .. })
    ));
}

#[tokio::test]
async fn the_status_survives_an_interval_that_is_out_of_range() {
    let provider =
        ScriptedProvider::with_interval(vec![Ok(snapshot("a"))], Duration::from_secs(u64::MAX));
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let status = status_of(&bots, ProviderId::new("scripted"));
    assert_eq!(status.next_refresh_at, None);
}

#[tokio::test]
async fn the_attribution_of_a_loaded_list_is_reachable() {
    let provider = ScriptedProvider::new(vec![Ok(snapshot("a"))]);
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    assert_eq!(
        bots.feed_attribution(&ProviderId::new("scripted")),
        Some(String::new())
    );
    assert!(
        bots.feed_header_lines(&ProviderId::new("scripted"))
            .is_empty()
    );
}

#[tokio::test]
async fn a_replaced_list_is_never_seen_half_parsed() {
    let provider = ScriptedProvider::new(vec![Ok(snapshot("a")), Ok(snapshot("b"))]);
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    let done = Arc::new(AtomicBool::new(false));
    let reader = tokio::spawn({
        let bots = bots.clone();
        let done = Arc::clone(&done);
        async move {
            let mut seen = Vec::new();
            while !done.load(Ordering::SeqCst) {
                let verdict = bots.assess_ip(address("45.32.1.1"));
                let generations: Vec<String> = verdict
                    .evidence
                    .iter()
                    .map(|evidence| {
                        evidence
                            .upstream_values
                            .get("generation")
                            .cloned()
                            .unwrap_or_default()
                    })
                    .collect();
                if !generations.is_empty() {
                    assert!(
                        generations
                            .iter()
                            .all(|generation| *generation == generations[0]),
                        "the verdict mixes two lists: {generations:?}"
                    );
                    seen.push(generations[0].clone());
                }
                tokio::task::yield_now().await;
            }
            seen
        }
    });

    for _ in 0..50 {
        bots.refresh_feeds().await;
        tokio::task::yield_now().await;
    }
    done.store(true, Ordering::SeqCst);

    let seen = reader.await.expect("the reader finishes");
    assert!(seen.contains(&"a".to_string()));
    assert!(seen.contains(&"b".to_string()));
}

#[tokio::test]
async fn a_list_that_is_replaced_releases_the_previous_one() {
    let provider = ScriptedProvider::new(vec![Ok(snapshot("a")), Ok(snapshot("b"))]);
    let bots = BadBots::builder()
        .feed_provider(provider.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;
    bots.refresh_feeds().await;

    let statuses = bots.provider_status();
    let status = statuses
        .iter()
        .find(|status| status.provider == ProviderId::new("scripted"))
        .expect("the provider is reported");
    assert_eq!(status.entries, Some(2));
}

#[tokio::test]
async fn the_status_reports_the_entries_and_the_next_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config_for_spamhaus(&server.uri()))
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let status = status_of(&bots, ProviderId::SPAMHAUS);
    assert_eq!(status.entries, Some(3));
    assert_eq!(
        status.published_at,
        Some(datetime!(2025-01-01 00:00:00 UTC))
    );
    assert_eq!(
        status.next_refresh_at,
        Some(now() + Duration::from_secs(60 * 60))
    );
    assert!(status.last_success.is_some());
}

#[tokio::test]
async fn the_coverage_reports_the_lists_that_were_consulted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config_for_spamhaus(&server.uri()))
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("1.10.16.5"));
    assert!(verdict.coverage.definitive.contains(&ProviderId::SPAMHAUS));

    let verdict = bots.assess_ip(address("9.9.9.9"));
    assert!(verdict.coverage.partial.contains(&ProviderId::SPAMHAUS));
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
}

#[tokio::test]
async fn a_list_alone_never_convicts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let bots = BadBots::builder()
        .config(config_for_spamhaus(&server.uri()))
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("1.10.16.5"));
    assert_eq!(verdict.classification, Classification::Suspect);
    assert_eq!(verdict.reason, VerdictReason::EvidencePresent);
}

#[tokio::test]
async fn a_list_and_another_family_convict() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/threatintel.txt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("dshield/threatintel.txt")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("dshield/block.txt")))
        .mount(&server)
        .await;

    let mut config = config_for_spamhaus(&server.uri());
    config.providers.dshield = Some(DShieldConfig {
        enabled: true,
        min_refresh_interval: None,
        user_agent: None,
        base_url: Some(server.uri()),
    });

    let bots = BadBots::builder()
        .config(config)
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("1.10.16.5"));
    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
    assert!(
        verdict
            .evidence
            .iter()
            .any(|e| e.family == SourceFamily::SPAMHAUS)
    );
    assert!(
        verdict
            .evidence
            .iter()
            .any(|e| e.family == SourceFamily::DSHIELD)
    );
}

#[tokio::test]
async fn one_family_never_convicts_and_two_families_do() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("blocklist_de/api_attacks.json")),
        )
        .mount(&server)
        .await;

    let mut config = Config::default();
    config.providers.blocklist_de = Some(BlocklistDeConfig {
        enabled: true,
        window: None,
        min_refresh_interval: None,
        use_per_address_query: true,
        use_service_lists: false,
        daily_quota: None,
        api_base_url: Some(server.uri()),
        lists_base_url: None,
    });

    let bots = BadBots::builder()
        .config(config.clone())
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    let report = bots.enrich_ip(address("45.32.1.1")).await;
    assert_eq!(report.verdict.classification, Classification::Suspect);

    Mock::given(method("GET"))
        .and(path("/threatintel.txt"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("dshield/threatintel.txt")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/block.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("dshield/block.txt")))
        .mount(&server)
        .await;

    config.providers.dshield = Some(DShieldConfig {
        enabled: true,
        min_refresh_interval: None,
        user_agent: None,
        base_url: Some(server.uri()),
    });

    let bots = BadBots::builder()
        .config(config)
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;
    let report = bots.enrich_ip(address("45.32.1.1")).await;
    assert_eq!(report.verdict.classification, Classification::Bad);
}

#[tokio::test]
async fn a_refresh_does_not_disturb_the_cached_lookups() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api.php"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("blocklist_de/api_attacks.json")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v4.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v4.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/drop_v6.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("spamhaus/drop_v6.json")))
        .mount(&server)
        .await;

    let mut config = Config::default();
    config.providers.blocklist_de = Some(BlocklistDeConfig {
        enabled: true,
        window: None,
        min_refresh_interval: None,
        use_per_address_query: true,
        use_service_lists: false,
        daily_quota: None,
        api_base_url: Some(server.uri()),
        lists_base_url: None,
    });
    config.providers.spamhaus = Some(SpamhausConfig {
        enabled: true,
        min_refresh_interval: None,
        base_url: Some(server.uri()),
    });

    let bots = BadBots::builder()
        .config(config)
        .clock(Arc::new(TestClock::new(now())))
        .build()
        .expect("the library is built");

    bots.enrich_ip(address("45.32.1.1")).await;
    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(address("45.32.1.1"));
    assert!(
        verdict
            .evidence
            .iter()
            .any(|evidence| evidence.family == SourceFamily::BLOCKLIST_DE)
    );
}

/// The configuration of a library that reads the Spamhaus lists.
fn config_for_spamhaus(base_url: &str) -> Config {
    let mut config = Config::default();
    config.providers.spamhaus = Some(SpamhausConfig {
        enabled: true,
        min_refresh_interval: None,
        base_url: Some(base_url.to_string()),
    });
    config
}

/// The status of a provider.
fn status_of(bots: &BadBots, provider: ProviderId) -> ProviderStatus {
    bots.provider_status()
        .into_iter()
        .find(|status| status.provider == provider)
        .expect("the provider is reported")
}
