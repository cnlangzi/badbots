//! `badbots` assesses how likely an inbound request's source address is to be
//! hostile.
//!
//! The library is precision-first: an address is flagged only when a source
//! makes a specific, current and verifiable claim that it committed an attack.
//! The verdict is a rule over evidence rather than a score, so the same evidence
//! always yields the same verdict and the verdict can be explained.
//!
//! ```
//! use badbots::{BadBots, Config};
//!
//! let bots = BadBots::builder().config(Config::default()).build().unwrap();
//! let verdict = bots.assess_ip("45.32.1.1".parse().unwrap());
//! assert_eq!(verdict.classification, badbots::Classification::Unknown);
//! assert_eq!(verdict.reason, badbots::VerdictReason::NoCoverage);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod clock;
pub mod config;
pub mod engine;
pub mod error;
pub mod http;
pub mod model;
pub mod provider;
pub mod quota;
pub mod ratelimit;
pub mod secret;

pub use cache::TtlCache;
pub use clock::{Clock, FixedClock, SystemClock};
pub use config::{
    ABUSEIPDB_DEFAULT_BASE_URL, ABUSEIPDB_DEFAULT_DAILY_QUOTA, ABUSEIPDB_DEFAULT_MAX_AGE_DAYS,
    ABUSEIPDB_FEATURE, AbuseIpdbConfig, CROWDSEC_DEFAULT_BASE_URL, CROWDSEC_DEFAULT_MONTHLY_QUOTA,
    CROWDSEC_FEATURE, Config, CrowdSecConfig, NetworkScopePolicy, ProviderConfig, UserAgentConfig,
};
pub use engine::classify;
pub use error::{ConfigError, Error, ProviderError};
pub use model::{
    Assertion, BehaviorIntent, BotKind, BotVerdict, Classification, Coverage, CoverageLevel,
    Evidence, EvidenceStrength, IpVerdict, MatchScope, ObservationWindow, ProviderId,
    RequestVerdict, SourceFamily, Suppression, ThreatCategory, UaState, UserAgentMarkers,
    VerdictInput, VerdictReason,
};
pub use provider::{
    EnrichmentReport, FeedProvider, FeedRefreshReport, FeedRefreshResult, FeedSnapshot,
    LookupProvider, ProviderCapability, ProviderOutcome, ProviderStatus, ProviderVerdict,
};
pub use secret::ApiKey;

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::Semaphore;

use crate::cache::{CacheKey, Cached};
use crate::model::{is_assessable, normalize};
use crate::provider::ProviderHealth;
use crate::provider::lookup::ProviderRuntime;

/// The environment variable that carries the AbuseIPDB API key.
pub const ABUSEIPDB_API_KEY_ENV: &str = "BADBOTS_ABUSEIPDB_API_KEY";
/// The environment variable that carries the CrowdSec API key.
pub const CROWDSEC_API_KEY_ENV: &str = "BADBOTS_CROWDSEC_API_KEY";

/// The state the library keeps between lookups.
struct Inner {
    config: Config,
    providers: Vec<Arc<dyn LookupProvider>>,
    feed_providers: Vec<Arc<dyn FeedProvider>>,
    runtimes: HashMap<ProviderId, Arc<ProviderRuntime>>,
    cache: TtlCache<ProviderVerdict>,
    health: Mutex<HashMap<ProviderId, ProviderHealth>>,
    failures: Mutex<HashMap<CacheKey, (ProviderError, OffsetDateTime)>>,
    refreshes: Mutex<HashMap<ProviderId, OffsetDateTime>>,
    markers: UserAgentMarkers,
    clock: Arc<dyn Clock>,
    concurrency: Semaphore,
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
            .field("providers", &self.inner.providers.len())
            .field("feed_providers", &self.inner.feed_providers.len())
            .finish()
    }
}

impl BadBots {
    /// Starts the construction of a library instance.
    pub fn builder() -> BadBotsBuilder {
        BadBotsBuilder::default()
    }

    /// Classifies an address from local state only.
    ///
    /// The call performs no network I/O: it answers from the lookup results that
    /// are already cached.
    pub fn assess_ip(&self, ip: IpAddr) -> IpVerdict {
        let now = self.inner.clock.now();
        let ip = normalize(ip);
        let mut input = VerdictInput::new(ip);

        if !is_assessable(ip) {
            return classify(&input, &self.inner.config, now);
        }

        for provider in &self.inner.providers {
            let key = CacheKey {
                provider: provider.id(),
                ip,
            };
            if let Some(verdict) = self.inner.cache.get(&key, now) {
                self.merge(&mut input, provider.as_ref(), &verdict);
            }
        }

        self.merge_failures(&mut input, now);
        classify(&input, &self.inner.config, now)
    }

    /// Classifies the address and the user agent of a request.
    ///
    /// The user-agent dimension never changes the address verdict.
    pub fn assess_request(&self, ip: IpAddr, user_agent: Option<&str>) -> RequestVerdict {
        let ip_verdict = self.assess_ip(ip);
        let bot = model::classify_user_agent(user_agent, &self.inner.markers);
        RequestVerdict {
            ip: ip_verdict,
            bot,
        }
    }

    /// Looks the address up at every configured provider.
    ///
    /// The call is asynchronous and performs the network I/O. A result that is
    /// already cached is reused and costs no upstream request. The providers are
    /// consulted at the same time, so the call takes as long as the slowest
    /// provider rather than the sum of all of them.
    pub async fn enrich_ip(&self, ip: IpAddr) -> EnrichmentReport {
        let now = self.inner.clock.now();
        let ip = normalize(ip);
        let mut input = VerdictInput::new(ip);
        let mut outcomes = Vec::new();

        if !is_assessable(ip) {
            return EnrichmentReport {
                ip,
                verdict: classify(&input, &self.inner.config, now),
                outcomes,
            };
        }

        let lookups = self.inner.providers.iter().map(|provider| {
            let key = CacheKey {
                provider: provider.id(),
                ip,
            };
            let negative_ttl = self.inner.config.negative_ttl;
            async move {
                let _permit = self.inner.concurrency.acquire().await.ok();
                let result = self
                    .inner
                    .cache
                    .get_or_fetch(key.clone(), now, || async {
                        let verdict = provider.lookup(ip).await?;
                        let expires_at = verdict.expires_at.unwrap_or(now + negative_ttl);
                        Ok(Cached {
                            value: verdict,
                            expires_at,
                        })
                    })
                    .await;
                (provider, key, result)
            }
        });

        for (provider, key, result) in futures_util::future::join_all(lookups).await {
            self.record_attempt(provider.id(), now);

            match result {
                Ok(verdict) => {
                    self.record_success(provider.id(), now);
                    self.clear_failure(&key);
                    tracing::debug!(
                        provider = %provider.id(),
                        ip = %ip,
                        evidence = verdict.evidence.len(),
                        "provider lookup finished"
                    );
                    self.merge(&mut input, provider.as_ref(), &verdict);
                    outcomes.push(ProviderOutcome {
                        provider: provider.id(),
                        result: Ok(verdict),
                    });
                }
                Err(error) => {
                    self.record_failure(provider.id(), now, error.clone());
                    self.record_address_failure(&key, error.clone(), now);
                    tracing::warn!(
                        provider = %provider.id(),
                        ip = %ip,
                        error = %error,
                        "provider lookup failed"
                    );
                    input.coverage.record_failure(provider.id(), error.clone());
                    outcomes.push(ProviderOutcome {
                        provider: provider.id(),
                        result: Err(error),
                    });
                }
            }
        }

        let verdict = classify(&input, &self.inner.config, now);
        EnrichmentReport {
            ip,
            verdict,
            outcomes,
        }
    }

    /// Refreshes every configured feed.
    ///
    /// The call is asynchronous and performs the network I/O. The library never
    /// refreshes a feed on its own. A provider whose shortest refresh interval
    /// has not elapsed is not asked again.
    pub async fn refresh_feeds(&self) -> FeedRefreshReport {
        let now = self.inner.clock.now();
        let mut results = Vec::new();
        for provider in &self.inner.feed_providers {
            if let Some(remaining) = self.refresh_remaining(provider.as_ref(), now) {
                results.push(FeedRefreshResult {
                    provider: provider.id(),
                    result: Err(ProviderError::RateLimited {
                        retry_after: Some(remaining),
                    }),
                });
                continue;
            }
            let result = provider.fetch().await;
            if result.is_ok() {
                self.record_refresh(provider.id(), now);
            }
            results.push(FeedRefreshResult {
                provider: provider.id(),
                result,
            });
        }
        FeedRefreshReport { results }
    }

    /// The health of every configured provider.
    pub fn provider_status(&self) -> Vec<ProviderStatus> {
        let now = self.inner.clock.now();
        let health = match self.inner.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut statuses = Vec::new();

        if let Some(provider) = &self.inner.config.providers.abuseipdb {
            statuses.push(self.status_of(
                ProviderId::ABUSEIPDB,
                SourceFamily::ABUSEIPDB,
                ProviderCapability::Primary,
                provider.enabled,
                health.get(&ProviderId::ABUSEIPDB),
                now,
            ));
        }

        if let Some(provider) = &self.inner.config.providers.crowdsec {
            statuses.push(self.status_of(
                ProviderId::CROWDSEC,
                SourceFamily::CROWDSEC,
                ProviderCapability::Primary,
                provider.enabled,
                health.get(&ProviderId::CROWDSEC),
                now,
            ));
        }

        statuses
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
        let runtime = self.inner.runtimes.get(&provider);
        ProviderStatus {
            provider,
            family,
            capability,
            enabled,
            last_success: health.and_then(|health| health.last_success),
            last_attempt: health.and_then(|health| health.last_attempt),
            last_error: health.and_then(|health| health.last_error.clone()),
            budget_used: runtime.map(|runtime| runtime.quota().used(now)),
            budget_limit: runtime.map(|runtime| runtime.quota().limit()),
        }
    }

    fn merge(
        &self,
        input: &mut VerdictInput,
        provider: &dyn LookupProvider,
        verdict: &ProviderVerdict,
    ) {
        for evidence in &verdict.evidence {
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
            input.evidence.push(evidence);
        }
        if let Some(suppression) = verdict.suppression {
            input
                .suppressions
                .push((verdict.provider.clone(), suppression));
        }
        input
            .coverage
            .record_success(verdict.provider.clone(), verdict.coverage);
    }

    /// Adds the failures that were recorded for the assessed address.
    ///
    /// A failure belongs to the address it happened for, so the record is kept
    /// per address rather than per provider.
    fn merge_failures(&self, input: &mut VerdictInput, now: OffsetDateTime) {
        let ttl = self.failure_ttl();
        let mut failures = match self.inner.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.retain(|_, (_, at)| now - *at <= ttl);

        for provider in &self.inner.providers {
            let key = CacheKey {
                provider: provider.id(),
                ip: input.ip,
            };
            let Some((error, _)) = failures.get(&key) else {
                continue;
            };
            input.coverage.record_failure(provider.id(), error.clone());
        }
    }

    /// The time a failure stays attached to the address it happened for.
    fn failure_ttl(&self) -> time::Duration {
        let seconds = self
            .inner
            .config
            .negative_ttl
            .as_secs()
            .min(i64::MAX as u64);
        time::Duration::seconds(seconds as i64)
    }

    fn record_address_failure(&self, key: &CacheKey, error: ProviderError, now: OffsetDateTime) {
        let ttl = self.failure_ttl();
        let mut failures = match self.inner.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.retain(|_, (_, at)| now - *at <= ttl);
        failures.insert(key.clone(), (error, now));
    }

    fn clear_failure(&self, key: &CacheKey) {
        let mut failures = match self.inner.failures.lock() {
            Ok(failures) => failures,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.remove(key);
    }

    fn record_refresh(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut refreshes = match self.inner.refreshes.lock() {
            Ok(refreshes) => refreshes,
            Err(poisoned) => poisoned.into_inner(),
        };
        refreshes.insert(provider, now);
    }

    /// The time left before the provider may be asked again.
    fn refresh_remaining(
        &self,
        provider: &dyn FeedProvider,
        now: OffsetDateTime,
    ) -> Option<Duration> {
        let last = {
            let refreshes = match self.inner.refreshes.lock() {
                Ok(refreshes) => refreshes,
                Err(poisoned) => poisoned.into_inner(),
            };
            *refreshes.get(&provider.id())?
        };
        let elapsed = (now - last).unsigned_abs();
        provider.min_refresh_interval().checked_sub(elapsed)
    }

    fn record_attempt(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut health = match self.inner.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        health.entry(provider).or_default().last_attempt = Some(now);
    }

    fn record_success(&self, provider: ProviderId, now: OffsetDateTime) {
        let mut health = match self.inner.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = health.entry(provider).or_default();
        entry.last_attempt = Some(now);
        entry.last_success = Some(now);
        entry.last_error = None;
    }

    fn record_failure(&self, provider: ProviderId, now: OffsetDateTime, error: ProviderError) {
        let mut health = match self.inner.health.lock() {
            Ok(health) => health,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = health.entry(provider).or_default();
        entry.last_attempt = Some(now);
        entry.last_error = Some(error);
    }
}

/// The builder of a library instance.
#[derive(Default)]
pub struct BadBotsBuilder {
    config: Config,
    client: Option<reqwest::Client>,
    clock: Option<Arc<dyn Clock>>,
    markers: Option<UserAgentMarkers>,
    feed_providers: Vec<Arc<dyn FeedProvider>>,
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

    /// Sets the timeout of a single provider request.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Sets how long a negative lookup result is reused.
    pub fn negative_ttl(mut self, ttl: Duration) -> Self {
        self.config.negative_ttl = ttl;
        self
    }

    /// Sets how prefix-scoped observations may carry the verdict.
    pub fn network_scope_policy(mut self, policy: NetworkScopePolicy) -> Self {
        self.config.network_scope_policy = policy;
        self
    }

    /// Sets the number of lookups that may run at the same time.
    pub fn max_concurrent_enrichments(mut self, max: usize) -> Self {
        self.config.max_concurrent_enrichments = max;
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

    /// Adds a provider that publishes a list of addresses.
    pub fn feed_provider(mut self, provider: Arc<dyn FeedProvider>) -> Self {
        self.feed_providers.push(provider);
        self
    }

    /// Builds the library instance.
    ///
    /// A provider that is enabled in the configuration but whose crate feature
    /// was not compiled in is reported as [`ConfigError::MissingFeature`].
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

        let client = match self.client {
            Some(client) => client,
            None => http::build_client(config.request_timeout)?,
        };

        let clock = self.clock.unwrap_or_else(clock::system_clock);
        let registered = registered_providers(&config, &client, &clock)?;
        let mut providers: Vec<Arc<dyn LookupProvider>> = Vec::with_capacity(registered.len());
        let mut runtimes: HashMap<ProviderId, Arc<ProviderRuntime>> = HashMap::new();
        for entry in registered {
            runtimes.insert(entry.provider.id(), Arc::clone(&entry.runtime));
            providers.push(entry.provider);
        }

        let markers = self
            .markers
            .unwrap_or_else(|| config::markers_from_config(&config.user_agent));
        let concurrency = Semaphore::new(config.max_concurrent_enrichments.max(1));

        Ok(BadBots {
            inner: Arc::new(Inner {
                cache: TtlCache::new(config.cache_capacity),
                config,
                providers,
                feed_providers: self.feed_providers,
                runtimes,
                health: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
                refreshes: Mutex::new(HashMap::new()),
                markers,
                clock,
                concurrency,
            }),
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

    Ok(registered)
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
