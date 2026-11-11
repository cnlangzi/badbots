//! The behaviour of the verification and of the worker thread.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use badbots::provider::{
    FeedProvider, FeedSnapshot, LookupProvider, ProviderCapability, ProviderCost, ProviderFinding,
};
use badbots::{
    Assertion, BadBots, Classification, Config, CoverageLevel, Evidence, EvidenceStrength,
    MatchScope, ProviderError, ProviderId, ProviderRuntime, SourceFamily, ThreatCategory,
    VerdictReason, daily_guard,
};

fn ip() -> IpAddr {
    "45.32.1.1".parse().unwrap()
}

fn other_ip() -> IpAddr {
    "45.32.1.2".parse().unwrap()
}

/// What the providers of a test record about the calls they received.
#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<IpAddr>>,
    threads: Mutex<Vec<std::thread::ThreadId>>,
    fetches: AtomicUsize,
    running: AtomicUsize,
    peak: AtomicUsize,
}

impl Recorder {
    fn calls(&self) -> Vec<IpAddr> {
        self.calls
            .lock()
            .expect("the recorder is not poisoned")
            .clone()
    }

    fn threads(&self) -> Vec<std::thread::ThreadId> {
        self.threads
            .lock()
            .expect("the recorder is not poisoned")
            .clone()
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

/// The observation a provider that convicts reports.
fn observation(provider: ProviderId, family: SourceFamily) -> Evidence {
    Evidence {
        provider,
        family,
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
    }
}

/// A provider the test controls.
struct TestProvider {
    id: ProviderId,
    family: SourceFamily,
    capability: ProviderCapability,
    recorder: Arc<Recorder>,
    convicts: bool,
    delay: Option<Duration>,
}

#[async_trait]
impl LookupProvider for TestProvider {
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
        ProviderCost::Medium
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        self.recorder
            .calls
            .lock()
            .expect("the recorder is not poisoned")
            .push(ip);
        self.recorder
            .threads
            .lock()
            .expect("the recorder is not poisoned")
            .push(std::thread::current().id());

        let running = self.recorder.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.recorder.peak.fetch_max(running, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        self.recorder.running.fetch_sub(1, Ordering::SeqCst);

        let evidence = if self.convicts {
            vec![observation(self.id.clone(), self.family.clone())]
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

/// Builds the factory of a provider the test controls.
fn test_provider(
    recorder: Arc<Recorder>,
    id: &'static str,
    family: &'static str,
    capability: ProviderCapability,
    convicts: bool,
    delay: Option<Duration>,
) -> impl FnOnce(Arc<ProviderRuntime>) -> TestProvider + Send + 'static {
    move |_runtime| TestProvider {
        id: ProviderId::new(id),
        family: SourceFamily::new(family),
        capability,
        recorder,
        convicts,
        delay,
    }
}

/// A list provider the test controls.
struct TestFeed {
    recorder: Arc<Recorder>,
    capability: ProviderCapability,
    entries: Vec<Evidence>,
}

#[async_trait]
impl FeedProvider for TestFeed {
    fn id(&self) -> ProviderId {
        ProviderId::new("list")
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("list")
    }

    fn capability(&self) -> ProviderCapability {
        self.capability
    }

    fn min_refresh_interval(&self) -> Duration {
        Duration::from_secs(60 * 60)
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        self.recorder.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(FeedSnapshot {
            provider: self.id(),
            family: self.family(),
            published_at: None,
            retrieved_at: time::OffsetDateTime::now_utc(),
            expires_at: None,
            attribution: String::new(),
            header_lines: Vec::new(),
            entries: self.entries.clone(),
        })
    }
}

#[tokio::test]
async fn the_verification_answers_from_the_provider_and_the_answer_is_remembered() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(verdict.evidence[0].provider, ProviderId::new("primary"));

    let assessed = bots.assess_ip(ip());
    assert_eq!(assessed.classification, Classification::Bad);
    assert_eq!(
        assessed.coverage.definitive,
        vec![ProviderId::new("primary")]
    );
}

#[tokio::test]
async fn a_conviction_stops_the_sequence_of_providers() {
    let primary = Arc::new(Recorder::default());
    let corroborating = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&primary),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&corroborating),
                "corroborating",
                "corroborating",
                ProviderCapability::Corroborating,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(
        primary.calls().len(),
        1,
        "the primary provider was not asked"
    );
    assert!(
        corroborating.calls().is_empty(),
        "the corroborating provider was asked although the address was convicted"
    );

    let assessed = bots.assess_ip(ip());
    assert_eq!(assessed.classification, Classification::Bad);
    assert_eq!(
        assessed.coverage.definitive,
        vec![ProviderId::new("primary")]
    );
    assert!(
        !assessed
            .coverage
            .definitive
            .contains(&ProviderId::new("corroborating"))
    );
}

#[tokio::test]
async fn the_providers_that_cannot_convict_alone_are_asked_together() {
    let first = Arc::new(Recorder::default());
    let second = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&first),
                "first",
                "first",
                ProviderCapability::Corroborating,
                true,
                None,
            ),
        )
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&second),
                "second",
                "second",
                ProviderCapability::Corroborating,
                true,
                Some(Duration::from_millis(200)),
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(first.calls().len(), 1);
    assert_eq!(second.calls().len(), 1);

    let assessed = bots.assess_ip(ip());
    assert_eq!(
        assessed.coverage.definitive.len(),
        2,
        "the answer of the slower provider was not waited for"
    );
}

#[tokio::test]
async fn the_assessment_equals_the_verification_of_the_same_address() {
    let primary = Arc::new(Recorder::default());
    let corroborating = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&primary),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&corroborating),
                "corroborating",
                "corroborating",
                ProviderCapability::Corroborating,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;
    let assessed = bots.assess_ip(ip());

    assert_eq!(assessed.classification, verdict.classification);
    assert_eq!(assessed.reason, verdict.reason);
    assert_eq!(assessed.coverage, verdict.coverage);
    assert_eq!(assessed.evidence, verdict.evidence);
}

#[tokio::test]
async fn one_verification_runs_for_an_address() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                Some(Duration::from_millis(200)),
            ),
        )
        .build()
        .expect("the library is built");

    let mut handles = Vec::new();
    for _ in 0..16 {
        let bots = bots.clone();
        handles.push(tokio::spawn(async move { bots.verify_ip(ip()).await }));
    }

    for handle in handles {
        let verdict = handle.await.expect("the task finishes");
        assert_eq!(verdict.classification, Classification::Bad);
    }

    assert_eq!(
        recorder.calls().len(),
        1,
        "the provider was asked more than once"
    );
}

#[tokio::test]
async fn the_verification_that_runs_is_waited_for() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                Some(Duration::from_millis(200)),
            ),
        )
        .build()
        .expect("the library is built");

    let first = bots.clone();
    let handle = tokio::spawn(async move { first.verify_ip(ip()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let second = bots.verify_ip(ip()).await;
    assert_eq!(second.classification, Classification::Bad);
    assert_eq!(
        recorder.calls().len(),
        1,
        "a second verification was started"
    );

    handle.await.expect("the task finishes");
}

#[tokio::test]
async fn the_request_runs_on_the_worker_thread() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    let threads = recorder.threads();
    assert_eq!(threads.len(), 1);
    assert_ne!(
        threads[0],
        std::thread::current().id(),
        "the request ran on the runtime of the caller"
    );
}

#[tokio::test]
async fn the_assessment_queues_a_verification() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.assess_ip(ip());
    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);

    for _ in 0..100 {
        if !recorder.calls().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        recorder.calls().len(),
        1,
        "the assessment did not queue a verification"
    );
}

#[tokio::test]
async fn no_more_verifications_run_at_the_same_time_than_configured() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .max_concurrent_verifications(2)
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                Some(Duration::from_millis(200)),
            ),
        )
        .build()
        .expect("the library is built");

    let mut handles = Vec::new();
    for index in 1..=6u8 {
        let bots = bots.clone();
        let address = IpAddr::from([45, 32, 1, index]);
        handles.push(tokio::spawn(async move { bots.verify_ip(address).await }));
    }

    for handle in handles {
        handle.await.expect("the task finishes");
    }

    assert_eq!(recorder.calls().len(), 6);
    assert!(
        recorder.peak() >= 2,
        "the verifications did not run at the same time at all"
    );
    assert!(
        recorder.peak() <= 2,
        "{} verifications ran at the same time",
        recorder.peak()
    );
}

#[tokio::test]
async fn the_worker_never_fetches_a_list() {
    let feed = Arc::new(Recorder::default());
    let lookup = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&lookup),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .feed_provider(daily_guard(100), {
            let feed = Arc::clone(&feed);
            move |_runtime| TestFeed {
                recorder: feed,
                capability: ProviderCapability::Corroborating,
                entries: Vec::new(),
            }
        })
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(lookup.calls().len(), 1);
    assert_eq!(feed.fetches(), 0, "the worker fetched a list on its own");
}

#[tokio::test]
async fn the_loaded_lists_alone_convict_and_no_verification_is_queued() {
    let feed = Arc::new(Recorder::default());
    let lookup = Arc::new(Recorder::default());
    let mut upstream_values = BTreeMap::new();
    upstream_values.insert("address".to_string(), ip().to_string());

    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&lookup),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .feed_provider(daily_guard(100), {
            let feed = Arc::clone(&feed);
            move |_runtime| TestFeed {
                recorder: feed,
                capability: ProviderCapability::Primary,
                entries: vec![Evidence {
                    provider: ProviderId::new("list"),
                    family: SourceFamily::new("list"),
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
                    upstream_values,
                }],
            }
        })
        .build()
        .expect("the library is built");

    bots.refresh_feeds().await;

    let verdict = bots.assess_ip(ip());
    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(verdict.reason, VerdictReason::Convicted);

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        lookup.calls().is_empty(),
        "a verification was queued although the lists already convicted"
    );
}

/// A provider that fails with a panic.
struct PanickingProvider;

#[async_trait]
impl LookupProvider for PanickingProvider {
    fn id(&self) -> ProviderId {
        ProviderId::new("panicking")
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::new("panicking")
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Primary
    }

    fn cost(&self) -> ProviderCost {
        ProviderCost::Medium
    }

    async fn lookup(&self, _ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        panic!("the provider panicked");
    }
}

#[tokio::test]
async fn a_provider_that_panics_does_not_leave_the_caller_waiting() {
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(daily_guard(100), |_runtime| PanickingProvider)
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip(ip()).await;

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
}

#[tokio::test]
async fn a_non_routable_address_is_never_asked_about() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.verify_ip("127.0.0.1".parse().unwrap()).await;

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
    assert!(recorder.calls().is_empty(), "the provider was asked");
}

#[tokio::test]
async fn a_non_routable_address_is_never_verified_in_the_background() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    let verdict = bots.assess_ip("10.0.0.1".parse().unwrap());

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        recorder.calls().is_empty(),
        "a private address reached the provider"
    );
}

#[tokio::test]
async fn an_address_no_provider_can_be_asked_about_is_not_verified() {
    let bots = BadBots::builder()
        .config(Config::default())
        .build()
        .expect("the library is built");

    let verdict = bots.assess_ip(ip());

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoCoverage);
}

#[tokio::test]
async fn the_quota_of_a_provider_bounds_the_verifications() {
    let recorder = Arc::new(Recorder::default());
    let bots = BadBots::builder()
        .config(Config::default())
        .lookup_provider(
            daily_guard(100),
            test_provider(
                Arc::clone(&recorder),
                "primary",
                "primary",
                ProviderCapability::Primary,
                true,
                None,
            ),
        )
        .build()
        .expect("the library is built");

    bots.verify_ip(ip()).await;
    let verdict = bots.verify_ip(other_ip()).await;

    assert_eq!(verdict.classification, Classification::Bad);
    assert_eq!(recorder.calls().len(), 2);
}
