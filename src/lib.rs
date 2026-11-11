//! `badbots` assesses how likely an inbound request's source address is to be
//! hostile.
//!
//! The library is precision-first: an address is flagged only when a source
//! makes a specific, current and verifiable claim that it committed an attack.
//! The verdict is a rule over evidence rather than a score, so the same evidence
//! always yields the same verdict and the verdict can be explained.
//!
//! The host calls the library when it has already detected attack behaviour.
//! The library answers two questions about an inbound request: is this client a
//! bot, and is this address hostile. The bot question is free and may be asked
//! on every request, the address question costs quota and is asked only when
//! the host is already suspicious.
//!
//! ```
//! use badbots::{BadBots, Config};
//!
//! let bots = BadBots::builder().config(Config::default()).build().unwrap();
//!
//! // Free, synchronous, no provider involved.
//! let bot = bots.assess_user_agent(Some("curl/8.4.0"));
//! assert!(bot.is_bot);
//!
//! // The local answer; a verification of the address is queued.
//! let verdict = bots.assess_ip("45.32.1.1".parse().unwrap());
//! assert_eq!(verdict.classification, badbots::Classification::Unknown);
//! assert_eq!(verdict.reason, badbots::VerdictReason::NoCoverage);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cache;
pub mod clock;
pub mod config;
pub mod engine;
pub mod error;
pub mod feed;
pub mod http;
mod index;
pub mod model;
pub mod provider;
pub mod quota;
pub mod ratelimit;
pub mod secret;
mod worker;

pub use clock::{Clock, FixedClock, SystemClock};
pub use config::{
    ABUSEIPDB_DEFAULT_BASE_URL, ABUSEIPDB_DEFAULT_DAILY_QUOTA, ABUSEIPDB_DEFAULT_MAX_AGE_DAYS,
    ABUSEIPDB_FEATURE, AbuseIpdbConfig, BLOCKLIST_DE_DEFAULT_API_BASE_URL,
    BLOCKLIST_DE_DEFAULT_DAILY_QUOTA, BLOCKLIST_DE_DEFAULT_LISTS_BASE_URL,
    BLOCKLIST_DE_DEFAULT_MIN_REFRESH_INTERVAL, BLOCKLIST_DE_DEFAULT_WINDOW, BLOCKLIST_DE_FEATURE,
    BlocklistDeConfig, CROWDSEC_DEFAULT_BASE_URL, CROWDSEC_DEFAULT_MONTHLY_QUOTA, CROWDSEC_FEATURE,
    Config, CrowdSecConfig, DSHIELD_DEFAULT_BASE_URL, DSHIELD_DEFAULT_MIN_REFRESH_INTERVAL,
    DSHIELD_FEATURE, DShieldConfig, FEED_DEFAULT_DAILY_QUOTA, NetworkScopePolicy, ProviderConfig,
    SPAMHAUS_DEFAULT_BASE_URL, SPAMHAUS_DEFAULT_MIN_REFRESH_INTERVAL, SPAMHAUS_FEATURE,
    SpamhausConfig, UserAgentConfig,
};
pub use engine::classify;
pub use error::{ConfigError, ProviderError};
pub use feed::{LoadedFeed, LoadedFeeds};
pub use model::{
    Assertion, BehaviorIntent, BotKind, BotVerdict, Classification, Coverage, CoverageLevel,
    Evidence, EvidenceStrength, IpVerdict, MatchScope, ObservationWindow, ProviderId, SourceFamily,
    Suppression, ThreatCategory, UaState, UserAgentMarkers, VerdictInput, VerdictReason,
};
pub use provider::lookup::{ProviderRuntime, daily_guard, monthly_guard};
pub use provider::{
    FeedProvider, FeedRefreshReport, FeedRefreshResult, FeedSnapshot, LookupProvider,
    ProviderCapability, ProviderFinding, ProviderStatus,
};
pub use quota::{QuotaGuard, QuotaWindow};
pub use secret::ApiKey;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use time::{Date, OffsetDateTime, Time, UtcOffset};
use tokio::sync::Semaphore;

use crate::cache::{CacheKey, CacheValue, TtlCache};
use crate::model::{is_assessable, normalize};
use crate::provider::ProviderHealth;
use crate::worker::{Job, Verification, Worker};

/// The environment variable that carries the AbuseIPDB API key.
pub const ABUSEIPDB_API_KEY_ENV: &str = "BADBOTS_ABUSEIPDB_API_KEY";
/// The environment variable that carries the CrowdSec API key.
pub const CROWDSEC_API_KEY_ENV: &str = "BADBOTS_CROWDSEC_API_KEY";

/// The state the library keeps between lookups.
///
/// The handle of the library and the worker thread share this state, so an
/// answer that the worker produced is visible to the next assessment.
pub(crate) struct Shared {
    config: Config,
    providers: Vec<Arc<dyn LookupProvider>>,
    feed_providers: Vec<Arc<dyn FeedProvider>>,
    lookup_runtimes: HashMap<ProviderId, Arc<ProviderRuntime>>,
    feed_runtimes: HashMap<ProviderId, Arc<ProviderRuntime>>,
    cache: TtlCache<ProviderFinding>,
    health: Mutex<HashMap<ProviderId, ProviderHealth>>,
    refreshes: Mutex<HashMap<ProviderId, OffsetDateTime>>,
    feeds: RwLock<Arc<LoadedFeeds>>,
    markers: UserAgentMarkers,
    clock: Arc<dyn Clock>,
    concurrency: Semaphore,
    in_flight: Mutex<HashMap<IpAddr, Arc<Verification>>>,
}

impl Shared {
    /// The providers that may convict an address on their own.
    fn primary_providers(&self) -> impl Iterator<Item = &Arc<dyn LookupProvider>> {
        self.providers
            .iter()
            .filter(|provider| provider.capability() == ProviderCapability::Primary)
    }

    /// The providers that may only add a vote to another family's finding.
    fn corroborating_providers(&self) -> impl Iterator<Item = &Arc<dyn LookupProvider>> {
        self.providers
            .iter()
            .filter(|provider| provider.capability() != ProviderCapability::Primary)
    }

    /// The providers in the order a verification asks them.
    fn ordered_providers(&self) -> impl Iterator<Item = &Arc<dyn LookupProvider>> {
        self.primary_providers()
            .chain(self.corroborating_providers())
    }

    /// Composes the assessment of an address from the local state.
    ///
    /// The providers are read in the order a verification asks them in, and the
    /// reading stops as soon as the findings satisfy the conviction rule, so
    /// that the coverage of the assessment is the coverage a verification would
    /// report.
    fn compose(&self, ip: IpAddr, now: OffsetDateTime) -> IpVerdict {
        let mut input = VerdictInput::new(ip);

        if !is_assessable(ip) {
            return classify(&input, &self.config, now);
        }

        self.merge_feeds(&mut input);
        if self.is_convicted(&input, now) {
            return classify(&input, &self.config, now);
        }

        for provider in self.ordered_providers() {
            let key = CacheKey {
                provider: provider.id(),
                ip,
            };
            match self.cache.get(&key, now) {
                Some(CacheValue::Answer(finding)) => {
                    self.merge(&mut input, provider.as_ref(), &finding);
                }
                Some(CacheValue::Failure(error)) => {
                    input.coverage.record_failure(provider.id(), error);
                }
                None => {}
            }
            if self.is_convicted(&input, now) {
                return classify(&input, &self.config, now);
            }
        }

        classify(&input, &self.config, now)
    }

    /// Whether the findings that are collected so far satisfy the conviction
    /// rule.
    ///
    /// The rule is the classification of the decision engine, so the condition
    /// that ends the sequence of providers and the condition that produces the
    /// final assessment cannot drift apart.
    fn is_convicted(&self, input: &VerdictInput, now: OffsetDateTime) -> bool {
        classify(input, &self.config, now).classification == Classification::Bad
    }

    /// Adds the findings of a provider to the evidence.
    ///
    /// The identity of the provider is taken from the provider itself, not from
    /// the finding, so a finding cannot claim the identity of another provider.
    fn merge(
        &self,
        input: &mut VerdictInput,
        provider: &dyn LookupProvider,
        finding: &ProviderFinding,
    ) {
        for evidence in &finding.evidence {
            let mut evidence = evidence.clone();
            match provider.capability() {
                ProviderCapability::Primary => {}
                ProviderCapability::Corroborating => {
                    if evidence.strength == EvidenceStrength::Convicting {
                        evidence.strength = EvidenceStrength::Corroborating;
                    }
                }
                ProviderCapability::ContextOnly => continue,
            }
            evidence.family = provider.family();
            evidence.provider = provider.id();
            input.evidence.push(evidence);
        }
        if let Some(suppression) = finding.suppression {
            input.suppressions.push((provider.id(), suppression));
        }
        input
            .coverage
            .record_success(provider.id(), finding.coverage);
    }

    /// Adds the observations of the loaded feeds.
    ///
    /// A feed provider keeps the lineage of the observation it publishes, so a
    /// list that republishes another publisher's data does not count as a
    /// second vote.
    fn merge_feeds(&self, input: &mut VerdictInput) {
        let feeds = self.loaded_feeds();

        for provider in &self.feed_providers {
            if provider.capability() == ProviderCapability::ContextOnly {
                continue;
            }
            let Some(feed) = feeds.get(provider.id()) else {
                continue;
            };

            let mut matched = false;
            for observation in feed.lookup(input.ip) {
                let mut observation = observation;
                if provider.capability() == ProviderCapability::Corroborating
                    && observation.strength == EvidenceStrength::Convicting
                {
                    observation.strength = EvidenceStrength::Corroborating;
                }
                matched = true;
                input.evidence.push(observation);
            }

            if input.coverage.definitive.contains(&provider.id())
                || input.coverage.partial.contains(&provider.id())
            {
                continue;
            }
            input.coverage.record_success(
                provider.id(),
                if matched {
                    CoverageLevel::Definitive
                } else {
                    CoverageLevel::Partial
                },
            );
        }
    }

    /// The feeds that are currently loaded.
    fn loaded_feeds(&self) -> Arc<LoadedFeeds> {
        match self.feeds.read() {
            Ok(feeds) => Arc::clone(&feeds),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Installs a snapshot and the index built from it.
    ///
    /// The index is built before the snapshot is installed, so a reader never
    /// sees a snapshot that is not indexed yet.
    fn install(&self, provider: ProviderId, snapshot: FeedSnapshot) {
        let feed = Arc::new(LoadedFeed::new(snapshot));

        let mut feeds = match self.feeds.write() {
            Ok(feeds) => feeds,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut registry = (**feeds).clone();
        registry.install(provider, feed);
        *feeds = Arc::new(registry);
    }

    /// The instant at which a provider may be asked again.
    fn next_refresh_at(&self, provider: &ProviderId) -> Option<OffsetDateTime> {
        let last = {
            let refreshes = match self.refreshes.lock() {
                Ok(refreshes) => refreshes,
                Err(poisoned) => poisoned.into_inner(),
            };
            *refreshes.get(provider)?
        };
        let interval = self
            .feed_providers
            .iter()
            .find(|feed| feed.id() == *provider)?
            .min_refresh_interval();

        last.checked_add(time::Duration::seconds(seconds_of(interval)))
    }

    /// The time left before the provider may be asked again.
    ///
    /// A provider whose interval has elapsed may be asked again.
    fn refresh_remaining(
        &self,
        provider: &dyn FeedProvider,
        now: OffsetDateTime,
    ) -> Option<Duration> {
        let last = {
            let refreshes = match self.refreshes.lock() {
                Ok(refreshes) => refreshes,
                Err(poisoned) => poisoned.into_inner(),
            };
            *refreshes.get(&provider.id())?
        };
        let elapsed = (now - last).unsigned_abs();
        let remaining = provider.min_refresh_interval().checked_sub(elapsed)?;

        if remaining.is_zero() {
            return None;
        }
        Some(remaining)
    }

    fn record_refresh(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut refreshes = match self.refreshes.lock() {
            Ok(refreshes) => refreshes,
            Err(poisoned) => poisoned.into_inner(),
        };
        refreshes.insert(provider, now);
    }

    fn record_attempt(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut health = match self.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        health.entry(provider).or_default().last_attempt = Some(now);
    }

    fn record_success(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut health = match self.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = health.entry(provider).or_default();
        entry.last_attempt = Some(now);
        entry.last_success = Some(now);
        entry.last_error = None;
    }

    fn record_failure(&self, provider: ProviderId, now: OffsetDateTime, error: ProviderError) {
        let mut health = match self.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = health.entry(provider).or_default();
        entry.last_attempt = Some(now);
        entry.last_error = Some(error);
    }
}

/// The state behind the handle of the library.
///
/// The state is dropped when the last handle of the library is dropped, and
/// the worker thread is stopped with it.
struct Inner {
    shared: Arc<Shared>,
    worker: Worker,
}

impl Inner {
    /// Makes sure that a verification of the address runs.
    ///
    /// The verification that runs for the address is returned when there is
    /// one, so that a caller waits for it instead of starting a second one.
    fn ensure_verification(&self, ip: IpAddr) -> Arc<Verification> {
        let verification = {
            let mut in_flight = lock(&self.shared.in_flight);
            if let Some(running) = in_flight.get(&ip) {
                return Arc::clone(running);
            }
            let verification = Verification::new(ip);
            in_flight.insert(ip, Arc::clone(&verification));
            verification
        };

        self.worker.enqueue(Job {
            ip,
            verification: Arc::clone(&verification),
        });
        verification
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.worker.stop();
    }
}

/// The library handle.
///
/// The handle is cheap to clone and holds its state behind an [`Arc`].
#[derive(Clone)]
pub struct BadBots {
    inner: Arc<Inner>,
}

impl fmt::Debug for BadBots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BadBots")
            .field("providers", &self.inner.shared.providers.len())
            .field("feed_providers", &self.inner.shared.feed_providers.len())
            .finish()
    }
}

impl BadBots {
    /// Starts the construction of a library instance.
    pub fn builder() -> BadBotsBuilder {
        BadBotsBuilder::default()
    }

    /// Classifies an address from the local state.
    ///
    /// The call performs no network I/O: it answers from the answers that are
    /// already cached, from the failures that are already remembered and from
    /// the lists that are already loaded.
    ///
    /// The assessment is composed in the order a verification asks the
    /// providers in, and it stops reading as soon as the findings satisfy the
    /// conviction rule, so that the coverage it reports is the coverage a
    /// verification would report.
    ///
    /// An assessment that is not `Bad` makes sure that a verification of the
    /// address runs, so that the answer becomes more precise without the caller
    /// waiting for it.
    pub fn assess_ip(&self, ip: IpAddr) -> IpVerdict {
        let shared = &self.inner.shared;
        let now = shared.clock.now();
        let ip = normalize(ip);
        let verdict = shared.compose(ip, now);

        if verdict.classification != Classification::Bad {
            self.inner.ensure_verification(ip);
        }
        verdict
    }

    /// Classifies the user agent of a request.
    ///
    /// The call performs no network I/O, spends no quota and touches no cache.
    /// The user-agent dimension never changes the address verdict.
    pub fn assess_user_agent(&self, user_agent: Option<&str>) -> BotVerdict {
        model::classify_user_agent(user_agent, &self.inner.shared.markers)
    }

    /// Waits for the verification of an address and returns its assessment.
    ///
    /// The call is asynchronous: it waits for the providers to answer. The
    /// requests themselves run on the worker thread of the library, never on
    /// the runtime of the caller.
    ///
    /// A verification that already runs for the address is waited for rather
    /// than started a second time. The answers and the failures of the
    /// verification are remembered, so that the next assessment of the address
    /// reports them without another request.
    pub async fn verify_ip(&self, ip: IpAddr) -> IpVerdict {
        let shared = &self.inner.shared;
        let ip = normalize(ip);
        let now = shared.clock.now();

        if !is_assessable(ip) {
            return classify(&VerdictInput::new(ip), &shared.config, now);
        }

        let verification = self.inner.ensure_verification(ip);
        verification.wait(&shared.config).await
    }

    /// Refreshes every configured feed.
    ///
    /// The call is asynchronous and performs the network I/O. The library never
    /// refreshes a feed on its own. A provider whose shortest refresh interval
    /// has not elapsed is not asked again and is reported with the time that is
    /// left. A provider that fails keeps the snapshot it had.
    ///
    /// The interval of a provider applies to a failed refresh as well, so that
    /// a publisher that is unreachable is not asked again and again.
    pub async fn refresh_feeds(&self) -> FeedRefreshReport {
        let shared = &self.inner.shared;
        let now = shared.clock.now();
        let mut skipped: Vec<(usize, FeedRefreshResult)> = Vec::new();
        let mut due: Vec<(usize, &Arc<dyn FeedProvider>)> = Vec::new();

        for (position, provider) in shared.feed_providers.iter().enumerate() {
            if let Some(remaining) = shared.refresh_remaining(provider.as_ref(), now) {
                skipped.push((
                    position,
                    FeedRefreshResult {
                        provider: provider.id(),
                        result: Err(ProviderError::RateLimited {
                            retry_after: Some(remaining),
                        }),
                    },
                ));
                continue;
            }
            due.push((position, provider));
        }

        let fetched = futures_util::future::join_all(
            due.iter()
                .map(|(_, provider)| async move { (provider.id(), provider.fetch().await) }),
        )
        .await;

        let mut results = skipped;
        for ((position, _), (id, result)) in due.into_iter().zip(fetched) {
            shared.record_attempt(id.clone(), now);
            shared.record_refresh(id.clone(), now);

            match &result {
                Ok(snapshot) => {
                    shared.record_success(id.clone(), now);
                    shared.install(id.clone(), snapshot.clone());
                }
                Err(error) => shared.record_failure(id.clone(), now, error.clone()),
            }

            results.push((
                position,
                FeedRefreshResult {
                    provider: id,
                    result,
                },
            ));
        }

        results.sort_by_key(|(position, _)| *position);
        FeedRefreshReport {
            results: results.into_iter().map(|(_, result)| result).collect(),
        }
    }

    /// The attribution of a loaded list.
    ///
    /// The upstream asks for its credit and its terms to be reproduced when the
    /// derived data is displayed or redistributed.
    pub fn feed_attribution(&self, provider: ProviderId) -> Option<String> {
        let feeds = self.inner.shared.loaded_feeds();
        feeds
            .get(provider)
            .map(|feed| feed.snapshot.attribution.clone())
    }

    /// The header lines of a loaded list.
    pub fn feed_header_lines(&self, provider: ProviderId) -> Vec<String> {
        let feeds = self.inner.shared.loaded_feeds();
        feeds
            .get(provider)
            .map(|feed| feed.snapshot.header_lines.clone())
            .unwrap_or_default()
    }

    /// The health of every provider the library consults.
    ///
    /// A provider the host registered is reported as well, whether the
    /// configuration declares it or not.
    pub fn provider_status(&self) -> Vec<ProviderStatus> {
        let shared = &self.inner.shared;
        let now = shared.clock.now();
        let health = match shared.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut statuses = Vec::new();
        let registered: Vec<ProviderId> = shared
            .providers
            .iter()
            .map(|provider| provider.id())
            .collect();

        if let Some(provider) = &shared.config.providers.abuseipdb
            && !registered.contains(&ProviderId::ABUSEIPDB)
        {
            statuses.push(shared.status_of(
                ProviderId::ABUSEIPDB,
                SourceFamily::ABUSEIPDB,
                ProviderCapability::Primary,
                provider.enabled,
                health.get(&ProviderId::ABUSEIPDB),
                now,
            ));
        }

        if let Some(provider) = &shared.config.providers.crowdsec
            && !registered.contains(&ProviderId::CROWDSEC)
        {
            statuses.push(shared.status_of(
                ProviderId::CROWDSEC,
                SourceFamily::CROWDSEC,
                ProviderCapability::Primary,
                provider.enabled,
                health.get(&ProviderId::CROWDSEC),
                now,
            ));
        }

        if let Some(provider) = &shared.config.providers.blocklist_de
            && provider.use_per_address_query
            && !registered.contains(&ProviderId::BLOCKLIST_DE)
        {
            statuses.push(shared.status_of(
                ProviderId::BLOCKLIST_DE,
                SourceFamily::BLOCKLIST_DE,
                ProviderCapability::Corroborating,
                provider.enabled,
                health.get(&ProviderId::BLOCKLIST_DE),
                now,
            ));
        }

        for provider in &shared.providers {
            statuses.push(shared.status_of(
                provider.id(),
                provider.family(),
                provider.capability(),
                true,
                health.get(&provider.id()),
                now,
            ));
        }

        let mut reported = Vec::new();
        for (provider, family, enabled) in shared.configured_feed_providers() {
            reported.push(provider.clone());
            let provider_health = health.get(&provider);
            statuses.push(shared.feed_status_of(
                provider,
                family,
                ProviderCapability::Corroborating,
                enabled,
                provider_health,
                now,
            ));
        }

        for provider in &shared.feed_providers {
            if reported.contains(&provider.id()) {
                continue;
            }
            statuses.push(shared.feed_status_of(
                provider.id(),
                provider.family(),
                provider.capability(),
                true,
                health.get(&provider.id()),
                now,
            ));
        }

        statuses
    }
}

impl Shared {
    /// The list providers the configuration asks for.
    fn configured_feed_providers(&self) -> Vec<(ProviderId, SourceFamily, bool)> {
        let mut configured = Vec::new();

        if let Some(provider) = &self.config.providers.spamhaus {
            configured.push((
                ProviderId::SPAMHAUS,
                SourceFamily::SPAMHAUS,
                provider.enabled,
            ));
        }

        if let Some(provider) = &self.config.providers.dshield {
            configured.push((ProviderId::DSHIELD, SourceFamily::DSHIELD, provider.enabled));
        }

        if let Some(provider) = &self.config.providers.blocklist_de
            && provider.use_service_lists
        {
            configured.push((
                ProviderId::BLOCKLIST_DE_LISTS,
                SourceFamily::BLOCKLIST_DE,
                provider.enabled,
            ));
        }

        configured
    }

    fn status_of(
        &self,
        provider: ProviderId,
        family: SourceFamily,
        capability: ProviderCapability,
        enabled: bool,
        health: Option<&ProviderHealth>,
        now: OffsetDateTime,
    ) -> ProviderStatus {
        let runtime = self.lookup_runtimes.get(&provider);
        ProviderStatus {
            provider,
            family,
            capability,
            enabled,
            last_success: health.and_then(|health| health.last_success),
            last_attempt: health.and_then(|health| health.last_attempt),
            last_error: health.and_then(|health| health.last_error.clone()),
            quota_used: runtime.map(|runtime| runtime.quota().used(now)),
            quota_limit: runtime.and_then(|runtime| runtime.quota().bounded_limit()),
            entries: None,
            published_at: None,
            next_refresh_at: None,
        }
    }

    fn feed_status_of(
        &self,
        provider: ProviderId,
        family: SourceFamily,
        capability: ProviderCapability,
        enabled: bool,
        health: Option<&ProviderHealth>,
        now: OffsetDateTime,
    ) -> ProviderStatus {
        let runtime = self.feed_runtimes.get(&provider);
        let feeds = self.loaded_feeds();
        let feed = feeds.get(provider.clone());
        let next_refresh_at = self.next_refresh_at(&provider);

        ProviderStatus {
            provider,
            family,
            capability,
            enabled,
            last_success: health.and_then(|health| health.last_success),
            last_attempt: health.and_then(|health| health.last_attempt),
            last_error: health.and_then(|health| health.last_error.clone()),
            quota_used: runtime.map(|runtime| runtime.quota().used(now)),
            quota_limit: runtime.and_then(|runtime| runtime.quota().bounded_limit()),
            entries: feed
                .map(|feed| u32::try_from(feed.snapshot.entries.len()).unwrap_or(u32::MAX)),
            published_at: feed.and_then(|feed| feed.snapshot.published_at),
            next_refresh_at,
        }
    }
}

/// The builder of a library instance.
#[derive(Default)]
pub struct BadBotsBuilder {
    config: Config,
    client: Option<reqwest::Client>,
    clock: Option<Arc<dyn Clock>>,
    markers: Option<UserAgentMarkers>,
    lookup_registrations: Vec<LookupRegistration>,
    feed_registrations: Vec<FeedRegistration>,
}

/// A lookup provider the host registered and the factory that builds it.
struct LookupRegistration {
    quota: QuotaGuard,
    factory: Box<dyn FnOnce(Arc<ProviderRuntime>) -> Arc<dyn LookupProvider> + Send>,
}

/// A feed provider the host registered and the factory that builds it.
struct FeedRegistration {
    quota: QuotaGuard,
    factory: Box<dyn FnOnce(Arc<ProviderRuntime>) -> Arc<dyn FeedProvider> + Send>,
}

impl BadBotsBuilder {
    /// Sets the whole configuration.
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Sets the API key of the AbuseIPDB provider.
    pub fn abuseipdb_api_key(mut self, key: impl Into<ApiKey>) -> Self {
        let provider = self
            .config
            .providers
            .abuseipdb
            .get_or_insert_with(AbuseIpdbConfig::default);
        provider.api_key = Some(key.into());
        self
    }

    /// Sets the API key of the CrowdSec provider.
    pub fn crowdsec_api_key(mut self, key: impl Into<ApiKey>) -> Self {
        let provider = self
            .config
            .providers
            .crowdsec
            .get_or_insert_with(CrowdSecConfig::default);
        provider.api_key = Some(key.into());
        self
    }

    /// Enables the AbuseIPDB provider.
    pub fn enable_abuseipdb(mut self) -> Self {
        let provider = self
            .config
            .providers
            .abuseipdb
            .get_or_insert_with(AbuseIpdbConfig::default);
        provider.enabled = true;
        self
    }

    /// Enables the CrowdSec provider.
    pub fn enable_crowdsec(mut self) -> Self {
        let provider = self
            .config
            .providers
            .crowdsec
            .get_or_insert_with(CrowdSecConfig::default);
        provider.enabled = true;
        self
    }

    /// Enables the Spamhaus DROP provider.
    pub fn enable_spamhaus(mut self) -> Self {
        let provider = self
            .config
            .providers
            .spamhaus
            .get_or_insert_with(SpamhausConfig::default);
        provider.enabled = true;
        self
    }

    /// Enables the Blocklist.de provider.
    pub fn enable_blocklist_de(mut self) -> Self {
        let provider = self
            .config
            .providers
            .blocklist_de
            .get_or_insert_with(BlocklistDeConfig::default);
        provider.enabled = true;
        self
    }

    /// Enables the DShield provider.
    pub fn enable_dshield(mut self) -> Self {
        let provider = self
            .config
            .providers
            .dshield
            .get_or_insert_with(DShieldConfig::default);
        provider.enabled = true;
        self
    }

    /// Sets the timeout of a single provider request.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Sets how long a positive lookup result is reused.
    pub fn positive_ttl(mut self, ttl: Duration) -> Self {
        self.config.positive_ttl = ttl;
        self
    }

    /// Sets how long a negative lookup result is reused.
    pub fn negative_ttl(mut self, ttl: Duration) -> Self {
        self.config.negative_ttl = ttl;
        self
    }

    /// Sets how long a failed lookup is remembered before the provider is asked
    /// again.
    pub fn failure_ttl(mut self, ttl: Duration) -> Self {
        self.config.failure_ttl = ttl;
        self
    }

    /// Sets how prefix-scoped observations may carry the verdict.
    pub fn network_scope_policy(mut self, policy: NetworkScopePolicy) -> Self {
        self.config.network_scope_policy = policy;
        self
    }

    /// Sets the number of verifications that may run at the same time.
    pub fn max_concurrent_verifications(mut self, max: usize) -> Self {
        self.config.max_concurrent_verifications = max;
        self
    }

    /// Sets the number of cached lookup results.
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.config.cache_capacity = capacity;
        self
    }

    /// Uses the HTTP client the host application supplies.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Uses the clock the host application supplies.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Uses the user-agent marker lists the host application supplies.
    pub fn user_agent_markers(mut self, markers: UserAgentMarkers) -> Self {
        self.markers = Some(markers);
        self
    }

    /// Registers a provider that is asked about one address at a time.
    ///
    /// The library builds the provider while it builds the library and hands it
    /// the runtime the provider performs its requests in: the HTTP client the
    /// host configured, the clock the host injected, the configured request
    /// timeout and the quota of the registration. A provider that brought its
    /// own runtime would answer with another clock and would not spend the
    /// quota the status reports.
    ///
    /// The requests of a registered provider run on the worker thread of the
    /// library, like the requests of every other provider.
    ///
    /// The identifier of the provider has to be unique, because the answers of
    /// a provider are cached under its identifier. A build with two providers
    /// of the same identifier fails with [`ConfigError::Invalid`].
    ///
    /// ```
    /// use std::net::IpAddr;
    /// use std::sync::Arc;
    ///
    /// use async_trait::async_trait;
    /// use badbots::provider::{LookupProvider, ProviderCapability, ProviderFinding};
    /// use badbots::{
    ///     BadBots, Config, CoverageLevel, ProviderError, ProviderId, ProviderRuntime,
    ///     SourceFamily, daily_guard,
    /// };
    ///
    /// struct InternalProvider {
    ///     runtime: Arc<ProviderRuntime>,
    /// }
    ///
    /// #[async_trait]
    /// impl LookupProvider for InternalProvider {
    ///     fn id(&self) -> ProviderId {
    ///         ProviderId::new("internal")
    ///     }
    ///
    ///     fn family(&self) -> SourceFamily {
    ///         SourceFamily::new("internal")
    ///     }
    ///
    ///     fn capability(&self) -> ProviderCapability {
    ///         ProviderCapability::Corroborating
    ///     }
    ///
    ///     async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
    ///         let now = self.runtime.clock().now();
    ///         let request = self.runtime.client().get("https://intel.internal/v1");
    ///         let response = self.runtime.send(request, now).await?;
    ///         let _body = self.runtime.read_body(response).await?;
    ///         Ok(ProviderFinding::empty(self.id(), CoverageLevel::Partial))
    ///     }
    /// }
    ///
    /// let bots = BadBots::builder()
    ///     .config(Config::default())
    ///     .lookup_provider(daily_guard(500), |runtime| {
    ///         Arc::new(InternalProvider { runtime })
    ///     })
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn lookup_provider<P, F>(mut self, quota: QuotaGuard, factory: F) -> Self
    where
        P: LookupProvider + 'static,
        F: FnOnce(Arc<ProviderRuntime>) -> P + Send + 'static,
    {
        self.lookup_registrations.push(LookupRegistration {
            quota,
            factory: Box::new(move |runtime| -> Arc<dyn LookupProvider> {
                Arc::new(factory(runtime))
            }),
        });
        self
    }

    /// Registers a provider that publishes a list of addresses.
    ///
    /// The provider is handed the same runtime as a lookup provider, so it
    /// spends the quota of the registration and uses the client and the clock
    /// of the host. A registered provider replaces a provider of the same
    /// identifier that the configuration asks for.
    pub fn feed_provider<P, F>(mut self, quota: QuotaGuard, factory: F) -> Self
    where
        P: FeedProvider + 'static,
        F: FnOnce(Arc<ProviderRuntime>) -> P + Send + 'static,
    {
        self.feed_registrations.push(FeedRegistration {
            quota,
            factory: Box::new(move |runtime| -> Arc<dyn FeedProvider> {
                Arc::new(factory(runtime))
            }),
        });
        self
    }

    /// Builds the library instance.
    ///
    /// A provider that is enabled in the configuration but whose crate feature
    /// was not compiled in is reported as [`ConfigError::MissingFeature`].
    ///
    /// The worker thread of the library starts when the first verification is
    /// queued, so building the library does not start it.
    pub fn build(self) -> Result<BadBots, ConfigError> {
        let config = self.config;

        if config.providers.abuseipdb_enabled() && !cfg!(feature = "abuseipdb") {
            return Err(ConfigError::MissingFeature {
                provider: ProviderId::ABUSEIPDB,
                feature: ABUSEIPDB_FEATURE,
            });
        }

        if config.providers.crowdsec_enabled() && !cfg!(feature = "crowdsec") {
            return Err(ConfigError::MissingFeature {
                provider: ProviderId::CROWDSEC,
                feature: CROWDSEC_FEATURE,
            });
        }

        if config.providers.spamhaus_enabled() && !cfg!(feature = "spamhaus") {
            return Err(ConfigError::MissingFeature {
                provider: ProviderId::SPAMHAUS,
                feature: SPAMHAUS_FEATURE,
            });
        }

        if config.providers.blocklist_de_enabled() && !cfg!(feature = "blocklist_de") {
            return Err(ConfigError::MissingFeature {
                provider: ProviderId::BLOCKLIST_DE,
                feature: BLOCKLIST_DE_FEATURE,
            });
        }

        if config.providers.dshield_enabled() && !cfg!(feature = "dshield") {
            return Err(ConfigError::MissingFeature {
                provider: ProviderId::DSHIELD,
                feature: DSHIELD_FEATURE,
            });
        }

        let client = match self.client {
            Some(client) => client,
            None => http::build_client(config.request_timeout)?,
        };

        let clock = self.clock.unwrap_or_else(clock::system_clock);
        let registered = registered_providers(&config, &client, &clock)?;
        let mut providers: Vec<Arc<dyn LookupProvider>> = Vec::with_capacity(registered.len());
        let mut lookup_runtimes: HashMap<ProviderId, Arc<ProviderRuntime>> = HashMap::new();
        let mut ids: Vec<ProviderId> = Vec::with_capacity(registered.len());
        for entry in registered {
            ids.push(entry.provider.id());
            lookup_runtimes.insert(entry.provider.id(), Arc::clone(&entry.runtime));
            providers.push(entry.provider);
        }

        for registration in self.lookup_registrations {
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                registration.quota,
                config.request_timeout,
                Arc::clone(&clock),
            ));
            let provider = (registration.factory)(Arc::clone(&runtime));
            let id = provider.id();
            if ids.contains(&id) {
                return Err(ConfigError::Invalid(format!("duplicate provider id {id}")));
            }
            ids.push(id.clone());
            lookup_runtimes.insert(id, runtime);
            providers.push(provider);
        }

        let mut feed_runtimes: HashMap<ProviderId, Arc<ProviderRuntime>> = HashMap::new();
        let mut feed_providers =
            registered_feed_providers(&config, &client, &clock, &mut feed_runtimes);
        for registration in self.feed_registrations {
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                registration.quota,
                config.request_timeout,
                Arc::clone(&clock),
            ));
            let provider = (registration.factory)(Arc::clone(&runtime));
            let id = provider.id();
            feed_providers.retain(|registered| registered.id() != id);
            feed_runtimes.remove(&id);
            feed_runtimes.insert(id, runtime);
            feed_providers.push(provider);
        }

        let markers = self
            .markers
            .unwrap_or_else(|| config::markers_from_config(&config.user_agent));
        let concurrency = Semaphore::new(config.max_concurrent_verifications.max(1));

        let shared = Arc::new(Shared {
            cache: TtlCache::new(config.cache_capacity, config.failure_ttl),
            config,
            providers,
            feed_providers,
            lookup_runtimes,
            feed_runtimes,
            health: Mutex::new(HashMap::new()),
            refreshes: Mutex::new(HashMap::new()),
            feeds: RwLock::new(Arc::new(LoadedFeeds::default())),
            markers,
            clock,
            concurrency,
            in_flight: Mutex::new(HashMap::new()),
        });
        let worker = Worker::new(Arc::clone(&shared));

        Ok(BadBots {
            inner: Arc::new(Inner { shared, worker }),
        })
    }
}

/// A provider and the runtime it performs its requests in.
struct RegisteredProvider {
    provider: Arc<dyn LookupProvider>,
    runtime: Arc<ProviderRuntime>,
}

#[cfg_attr(
    not(any(feature = "abuseipdb", feature = "crowdsec")),
    allow(unused_variables)
)]
fn registered_providers(
    config: &Config,
    client: &reqwest::Client,
    clock: &Arc<dyn Clock>,
) -> Result<Vec<RegisteredProvider>, ConfigError> {
    #[cfg_attr(
        not(any(feature = "abuseipdb", feature = "crowdsec")),
        allow(unused_mut)
    )]
    let mut registered = Vec::new();

    #[cfg(feature = "abuseipdb")]
    {
        let key = config
            .providers
            .abuseipdb
            .as_ref()
            .and_then(|provider| provider.api_key.clone())
            .or_else(|| api_key_from_env(ABUSEIPDB_API_KEY_ENV));

        if config.providers.abuseipdb_enabled() {
            let Some(key) = key else {
                return Err(ConfigError::MissingApiKey {
                    provider: ProviderId::ABUSEIPDB,
                });
            };
            let provider_config = config
                .providers
                .abuseipdb
                .as_ref()
                .expect("the provider is enabled");
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                provider::lookup::daily_guard(
                    provider_config
                        .daily_quota
                        .unwrap_or(ABUSEIPDB_DEFAULT_DAILY_QUOTA),
                ),
                config.request_timeout,
                Arc::clone(clock),
            ));
            let provider = provider::abuseipdb::AbuseIpdbProvider::new(
                key,
                provider_config
                    .base_url
                    .clone()
                    .unwrap_or_else(|| ABUSEIPDB_DEFAULT_BASE_URL.to_string()),
                provider_config
                    .max_age_days
                    .unwrap_or(ABUSEIPDB_DEFAULT_MAX_AGE_DAYS),
                Arc::clone(&runtime),
            );
            registered.push(RegisteredProvider {
                provider: Arc::new(provider),
                runtime,
            });
        }
    }

    #[cfg(feature = "crowdsec")]
    {
        let key = config
            .providers
            .crowdsec
            .as_ref()
            .and_then(|provider| provider.api_key.clone())
            .or_else(|| api_key_from_env(CROWDSEC_API_KEY_ENV));

        if config.providers.crowdsec_enabled() {
            let Some(key) = key else {
                return Err(ConfigError::MissingApiKey {
                    provider: ProviderId::CROWDSEC,
                });
            };
            let provider_config = config
                .providers
                .crowdsec
                .as_ref()
                .expect("the provider is enabled");
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                provider::lookup::monthly_guard(
                    provider_config
                        .monthly_quota
                        .unwrap_or(CROWDSEC_DEFAULT_MONTHLY_QUOTA),
                ),
                config.request_timeout,
                Arc::clone(clock),
            ));
            let provider = provider::crowdsec::CrowdSecProvider::new(
                key,
                provider_config
                    .base_url
                    .clone()
                    .unwrap_or_else(|| CROWDSEC_DEFAULT_BASE_URL.to_string()),
                provider_config.behavior_intents.clone().unwrap_or_default(),
                Arc::clone(&runtime),
            );
            registered.push(RegisteredProvider {
                provider: Arc::new(provider),
                runtime,
            });
        }
    }

    #[cfg(feature = "blocklist_de")]
    {
        if config.providers.blocklist_de_enabled() {
            let provider_config = config
                .providers
                .blocklist_de
                .as_ref()
                .expect("the provider is enabled");

            if provider_config.use_per_address_query {
                let runtime = Arc::new(ProviderRuntime::new(
                    client.clone(),
                    provider::lookup::daily_guard(
                        provider_config
                            .daily_quota
                            .unwrap_or(BLOCKLIST_DE_DEFAULT_DAILY_QUOTA),
                    ),
                    config.request_timeout,
                    Arc::clone(clock),
                ));
                let provider = provider::blocklist_de::BlocklistDeQueryProvider::new(
                    provider_config
                        .api_base_url
                        .clone()
                        .unwrap_or_else(|| BLOCKLIST_DE_DEFAULT_API_BASE_URL.to_string()),
                    provider_config
                        .window
                        .unwrap_or(BLOCKLIST_DE_DEFAULT_WINDOW),
                    Arc::clone(&runtime),
                );
                registered.push(RegisteredProvider {
                    provider: Arc::new(provider),
                    runtime,
                });
            }
        }
    }

    Ok(registered)
}

/// The list providers the configuration asks for.
#[cfg_attr(
    not(any(feature = "spamhaus", feature = "blocklist_de", feature = "dshield")),
    allow(unused_variables, unused_mut)
)]
fn registered_feed_providers(
    config: &Config,
    client: &reqwest::Client,
    clock: &Arc<dyn Clock>,
    runtimes: &mut HashMap<ProviderId, Arc<ProviderRuntime>>,
) -> Vec<Arc<dyn FeedProvider>> {
    let mut registered: Vec<Arc<dyn FeedProvider>> = Vec::new();

    #[cfg(feature = "spamhaus")]
    {
        if config.providers.spamhaus_enabled() {
            let provider_config = config
                .providers
                .spamhaus
                .as_ref()
                .expect("the provider is enabled");
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                provider::lookup::daily_guard(FEED_DEFAULT_DAILY_QUOTA),
                config.request_timeout,
                Arc::clone(clock),
            ));
            let provider = provider::spamhaus::SpamhausProvider::new(
                provider_config
                    .base_url
                    .clone()
                    .unwrap_or_else(|| SPAMHAUS_DEFAULT_BASE_URL.to_string()),
                provider_config
                    .min_refresh_interval
                    .unwrap_or(SPAMHAUS_DEFAULT_MIN_REFRESH_INTERVAL),
                Arc::clone(&runtime),
            );
            runtimes.insert(ProviderId::SPAMHAUS, Arc::clone(&runtime));
            registered.push(Arc::new(provider));
        }
    }

    #[cfg(feature = "blocklist_de")]
    {
        if config.providers.blocklist_de_enabled() {
            let provider_config = config
                .providers
                .blocklist_de
                .as_ref()
                .expect("the provider is enabled");

            if provider_config.use_service_lists {
                let runtime = Arc::new(ProviderRuntime::new(
                    client.clone(),
                    provider::lookup::daily_guard(FEED_DEFAULT_DAILY_QUOTA),
                    config.request_timeout,
                    Arc::clone(clock),
                ));
                let provider = provider::blocklist_de::BlocklistDeListProvider::new(
                    provider_config
                        .lists_base_url
                        .clone()
                        .unwrap_or_else(|| BLOCKLIST_DE_DEFAULT_LISTS_BASE_URL.to_string()),
                    provider_config
                        .min_refresh_interval
                        .unwrap_or(BLOCKLIST_DE_DEFAULT_MIN_REFRESH_INTERVAL),
                    Arc::clone(&runtime),
                );
                runtimes.insert(ProviderId::BLOCKLIST_DE_LISTS, Arc::clone(&runtime));
                registered.push(Arc::new(provider));
            }
        }
    }

    #[cfg(feature = "dshield")]
    {
        if config.providers.dshield_enabled() {
            let provider_config = config
                .providers
                .dshield
                .as_ref()
                .expect("the provider is enabled");
            let runtime = Arc::new(ProviderRuntime::new(
                client.clone(),
                provider::lookup::daily_guard(FEED_DEFAULT_DAILY_QUOTA),
                config.request_timeout,
                Arc::clone(clock),
            ));
            let provider = provider::dshield::DShieldProvider::new(
                provider_config
                    .base_url
                    .clone()
                    .unwrap_or_else(|| DSHIELD_DEFAULT_BASE_URL.to_string()),
                provider_config
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| provider::dshield::DEFAULT_USER_AGENT.to_string()),
                provider_config
                    .min_refresh_interval
                    .unwrap_or(DSHIELD_DEFAULT_MIN_REFRESH_INTERVAL),
                Arc::clone(&runtime),
            );
            runtimes.insert(ProviderId::DSHIELD, Arc::clone(&runtime));
            registered.push(Arc::new(provider));
        }
    }

    registered
}

#[cfg_attr(
    not(any(feature = "abuseipdb", feature = "crowdsec")),
    allow(dead_code)
)]
fn api_key_from_env(name: &str) -> Option<ApiKey> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(ApiKey::new)
}

/// The number of whole seconds of a duration.
fn seconds_of(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

/// Locks a mutex and recovers from a poisoned lock.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The instant at which a bound of the host expires.
///
/// A bound that reaches beyond the range of the clock ends at the end of that
/// range.
pub(crate) fn bound_expiry(now: OffsetDateTime, ttl: Duration) -> OffsetDateTime {
    let duration = time::Duration::try_from(ttl).unwrap_or(time::Duration::MAX);
    now.checked_add(duration)
        .unwrap_or_else(|| OffsetDateTime::new_in_offset(Date::MAX, Time::MAX, UtcOffset::UTC))
}

/// The instant at which a cached answer stops being usable.
///
/// The host bounds the lifetime of every answer: the entry expires at the
/// earlier of the expiry the provider declared and the bound for the kind of
/// result the answer carries. The bound can only make the library ask sooner,
/// it never keeps a claim alive past the validity the provider stated.
pub(crate) fn entry_expiry(
    finding: &ProviderFinding,
    config: &Config,
    now: OffsetDateTime,
) -> OffsetDateTime {
    let ttl = if finding.evidence.is_empty() {
        config.negative_ttl
    } else {
        config.positive_ttl
    };
    let bound = bound_expiry(now, ttl);
    match finding.expires_at {
        Some(declared) => declared.min(bound),
        None => bound,
    }
}
