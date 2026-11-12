//! Configuration of the library.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::BehaviorIntent;
use crate::secret::ApiKey;

/// How prefix-scoped observations are allowed to carry the verdict.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScopePolicy {
    /// A prefix-scoped observation may only add a vote to another family's
    /// observation. This is the default.
    #[default]
    CorroborateOnly,
    /// A prefix-scoped observation may also satisfy the single-source path.
    Allow,
}

/// How strict the evidence bar of a verdict is.
///
/// The policy is chosen once, when the library instance is built, because it
/// decides which providers are worth spending quota on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePolicy {
    /// One `Convicting` observation that satisfies the single-source condition,
    /// or two corroborating source families, are needed for a conviction. This
    /// is the default.
    #[default]
    Strict,
    /// Every valid observation that no provider withdrew is enough for a
    /// conviction.
    Lenient,
}

/// The user-agent marker lists.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct UserAgentConfig {
    /// Markers of a user agent that declares itself a crawler.
    ///
    /// Replaces the compiled-in list when set.
    #[serde(default)]
    pub crawler_markers: Option<Vec<String>>,
    /// Markers of a user agent that declares itself an automation tool.
    ///
    /// Replaces the compiled-in list when set.
    #[serde(default)]
    pub automation_markers: Option<Vec<String>>,
    /// Markers of a browser.
    ///
    /// Replaces the compiled-in list when set.
    #[serde(default)]
    pub browser_features: Option<Vec<String>>,
}

/// The AbuseIPDB check provider.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct AbuseIpdbConfig {
    /// Whether the provider is queried.
    #[serde(default)]
    pub enabled: bool,
    /// The API key supplied by the host application.
    #[serde(default)]
    pub api_key: Option<ApiKey>,
    /// The number of lookups per day the local budget guard allows.
    #[serde(default)]
    pub daily_quota: Option<u32>,
    /// The base URL of the check endpoint.
    #[serde(default)]
    pub base_url: Option<String>,
    /// The number of days of reports to request.
    #[serde(default)]
    pub max_age_days: Option<u32>,
}

/// The CrowdSec CTI provider.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    /// Whether the provider is queried.
    #[serde(default)]
    pub enabled: bool,
    /// The API key supplied by the host application.
    #[serde(default)]
    pub api_key: Option<ApiKey>,
    /// The number of lookups per month the local budget guard allows.
    #[serde(default)]
    pub monthly_quota: Option<u32>,
    /// The base URL of the smoke endpoint.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Overrides for the behavior intent table.
    ///
    /// The keys are behavior names as published by the source. The compiled-in
    /// table is used for every name this map does not contain.
    #[serde(default)]
    pub behavior_intents: Option<BTreeMap<String, BehaviorIntent>>,
}

/// The Spamhaus DROP list provider.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SpamhausConfig {
    /// Whether the provider is queried.
    #[serde(default)]
    pub enabled: bool,
    /// The shortest interval between two refreshes.
    #[serde(default)]
    pub min_refresh_interval: Option<Duration>,
    /// The base URL of the JSON lists.
    #[serde(default)]
    pub base_url: Option<String>,
}

/// The Blocklist.de provider.
///
/// The upstream publishes a per-address query and a set of per-service lists.
/// The two are independent products of the same publisher, so the query and the
/// lists can be switched on separately.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlocklistDeConfig {
    /// Whether the provider is queried.
    #[serde(default)]
    pub enabled: bool,
    /// The interval the per-address query asks about.
    #[serde(default)]
    pub window: Option<Duration>,
    /// The shortest interval between two refreshes of the service lists.
    #[serde(default)]
    pub min_refresh_interval: Option<Duration>,
    /// Whether the per-address query is used.
    #[serde(default = "default_true")]
    pub use_per_address_query: bool,
    /// Whether the per-service lists are used.
    #[serde(default = "default_true")]
    pub use_service_lists: bool,
    /// The number of queries per day the local budget guard allows.
    #[serde(default)]
    pub daily_quota: Option<u32>,
    /// The base URL of the per-address query.
    #[serde(default)]
    pub api_base_url: Option<String>,
    /// The base URL of the per-service lists.
    #[serde(default)]
    pub lists_base_url: Option<String>,
}

impl Default for BlocklistDeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window: None,
            min_refresh_interval: None,
            use_per_address_query: true,
            use_service_lists: true,
            daily_quota: None,
            api_base_url: None,
            lists_base_url: None,
        }
    }
}

/// The DShield list provider.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct DShieldConfig {
    /// Whether the provider is queried.
    #[serde(default)]
    pub enabled: bool,
    /// The shortest interval between two refreshes.
    #[serde(default)]
    pub min_refresh_interval: Option<Duration>,
    /// The user agent that identifies the operator.
    ///
    /// The publisher refuses requests that do not identify their sender.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// The base URL of the lists.
    #[serde(default)]
    pub base_url: Option<String>,
}

/// The configuration of every supported provider.
///
/// A provider is only compiled in by its own crate feature. A provider that is
/// enabled here but whose feature was not compiled in makes the build of the
/// library fail with
/// [`ConfigError::MissingFeature`](crate::ConfigError::MissingFeature).
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// The AbuseIPDB check provider.
    #[serde(default)]
    pub abuseipdb: Option<AbuseIpdbConfig>,
    /// The CrowdSec CTI provider.
    #[serde(default)]
    pub crowdsec: Option<CrowdSecConfig>,
    /// The Spamhaus DROP list provider.
    #[serde(default)]
    pub spamhaus: Option<SpamhausConfig>,
    /// The Blocklist.de provider.
    #[serde(default)]
    pub blocklist_de: Option<BlocklistDeConfig>,
    /// The DShield list provider.
    #[serde(default)]
    pub dshield: Option<DShieldConfig>,
}

/// The configuration of the library.
///
/// The crate reads no file and no environment variable on its own: a host
/// application supplies this structure.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The provider configuration.
    #[serde(default)]
    pub providers: ProviderConfig,
    /// The timeout of a single provider request.
    #[serde(default = "default_request_timeout")]
    pub request_timeout: Duration,
    /// How long a positive lookup result is reused.
    #[serde(default = "default_positive_ttl")]
    pub positive_ttl: Duration,
    /// How long a negative lookup result is reused.
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: Duration,
    /// How long a failed lookup is remembered before the provider is asked again.
    #[serde(default = "default_failure_ttl")]
    pub failure_ttl: Duration,
    /// How prefix-scoped observations may carry the verdict.
    #[serde(default)]
    pub network_scope_policy: NetworkScopePolicy,
    /// How strict the evidence bar of a verdict is.
    #[serde(default)]
    pub evidence_policy: EvidencePolicy,
    /// The number of verifications that may run at the same time.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,
    /// The number of cached lookup results.
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,
    /// The user-agent marker lists.
    #[serde(default)]
    pub user_agent: UserAgentConfig,
}

fn default_request_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_negative_ttl() -> Duration {
    Duration::from_secs(24 * 60 * 60)
}

fn default_positive_ttl() -> Duration {
    Duration::from_secs(30 * 24 * 60 * 60)
}

fn default_failure_ttl() -> Duration {
    Duration::from_secs(5 * 60)
}

fn default_max_concurrent_verifications() -> usize {
    4
}

fn default_cache_capacity() -> usize {
    10_000
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            providers: ProviderConfig::default(),
            request_timeout: default_request_timeout(),
            positive_ttl: default_positive_ttl(),
            negative_ttl: default_negative_ttl(),
            failure_ttl: default_failure_ttl(),
            network_scope_policy: NetworkScopePolicy::default(),
            evidence_policy: EvidencePolicy::default(),
            max_concurrent_verifications: default_max_concurrent_verifications(),
            cache_capacity: default_cache_capacity(),
            user_agent: UserAgentConfig::default(),
        }
    }
}

/// The identifier of the AbuseIPDB provider.
pub const ABUSEIPDB_FEATURE: &str = "abuseipdb";
/// The identifier of the CrowdSec provider.
pub const CROWDSEC_FEATURE: &str = "crowdsec";
/// The identifier of the Spamhaus provider.
pub const SPAMHAUS_FEATURE: &str = "spamhaus";
/// The identifier of the Blocklist.de provider.
pub const BLOCKLIST_DE_FEATURE: &str = "blocklist_de";
/// The identifier of the DShield provider.
pub const DSHIELD_FEATURE: &str = "dshield";

/// The upstream endpoint of the AbuseIPDB check API.
pub const ABUSEIPDB_DEFAULT_BASE_URL: &str = "https://api.abuseipdb.com/api/v2";
/// The upstream endpoint of the CrowdSec CTI API.
pub const CROWDSEC_DEFAULT_BASE_URL: &str = "https://cti.api.crowdsec.net/v2";
/// The upstream endpoint of the Spamhaus DROP lists.
pub const SPAMHAUS_DEFAULT_BASE_URL: &str = "https://www.spamhaus.org/drop";
/// The upstream endpoint of the Blocklist.de per-address query.
pub const BLOCKLIST_DE_DEFAULT_API_BASE_URL: &str = "https://api.blocklist.de";
/// The upstream endpoint of the Blocklist.de service lists.
pub const BLOCKLIST_DE_DEFAULT_LISTS_BASE_URL: &str = "https://lists.blocklist.de";
/// The upstream endpoint of the DShield lists.
pub const DSHIELD_DEFAULT_BASE_URL: &str = "https://feeds.dshield.org";

/// The default daily budget of the AbuseIPDB provider.
pub const ABUSEIPDB_DEFAULT_DAILY_QUOTA: u32 = 1_000;
/// The default monthly budget of the CrowdSec provider.
pub const CROWDSEC_DEFAULT_MONTHLY_QUOTA: u32 = 120;
/// The default number of days of reports requested from AbuseIPDB.
pub const ABUSEIPDB_DEFAULT_MAX_AGE_DAYS: u32 = 30;
/// The default daily budget of the Blocklist.de per-address query.
pub const BLOCKLIST_DE_DEFAULT_DAILY_QUOTA: u32 = 10_000;
/// The default daily budget of the list providers.
///
/// The budget of a list provider is separate from the budget of the
/// per-address query of Blocklist.de.
pub const FEED_DEFAULT_DAILY_QUOTA: u32 = 10_000;

/// The shortest interval between two Spamhaus refreshes.
pub const SPAMHAUS_DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// The shortest interval between two Blocklist.de refreshes.
pub const BLOCKLIST_DE_DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// The shortest interval between two DShield refreshes.
pub const DSHIELD_DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// The interval the Blocklist.de per-address query asks about.
pub const BLOCKLIST_DE_DEFAULT_WINDOW: Duration = Duration::from_secs(48 * 60 * 60);

impl ProviderConfig {
    /// Whether the AbuseIPDB provider is configured and enabled.
    pub fn abuseipdb_enabled(&self) -> bool {
        self.abuseipdb.as_ref().is_some_and(|c| c.enabled)
    }

    /// Whether the CrowdSec provider is configured and enabled.
    pub fn crowdsec_enabled(&self) -> bool {
        self.crowdsec.as_ref().is_some_and(|c| c.enabled)
    }

    /// Whether the Spamhaus provider is configured and enabled.
    pub fn spamhaus_enabled(&self) -> bool {
        self.spamhaus.as_ref().is_some_and(|c| c.enabled)
    }

    /// Whether the Blocklist.de provider is configured and enabled.
    pub fn blocklist_de_enabled(&self) -> bool {
        self.blocklist_de.as_ref().is_some_and(|c| c.enabled)
    }

    /// Whether the DShield provider is configured and enabled.
    pub fn dshield_enabled(&self) -> bool {
        self.dshield.as_ref().is_some_and(|c| c.enabled)
    }
}

/// The user-agent marker lists a configuration asks for.
///
/// A list that is not set keeps the compiled-in default.
pub fn markers_from_config(config: &UserAgentConfig) -> crate::model::UserAgentMarkers {
    let mut markers = crate::model::UserAgentMarkers::defaults();
    if let Some(list) = &config.crawler_markers {
        markers.crawler_markers = list.clone();
    }
    if let Some(list) = &config.automation_markers {
        markers.automation_markers = list.clone();
    }
    if let Some(list) = &config.browser_features {
        markers.browser_features = list.clone();
    }
    markers
}
