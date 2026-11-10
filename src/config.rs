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

/// The configuration of every supported provider.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// The AbuseIPDB check provider.
    #[serde(default)]
    pub abuseipdb: Option<AbuseIpdbConfig>,
    /// The CrowdSec CTI provider.
    #[serde(default)]
    pub crowdsec: Option<CrowdSecConfig>,
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
    /// How long a negative lookup result is reused.
    #[serde(default = "default_negative_ttl")]
    pub negative_ttl: Duration,
    /// How prefix-scoped observations may carry the verdict.
    #[serde(default)]
    pub network_scope_policy: NetworkScopePolicy,
    /// The number of lookups that may run at the same time.
    #[serde(default = "default_max_concurrent_enrichments")]
    pub max_concurrent_enrichments: usize,
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

fn default_max_concurrent_enrichments() -> usize {
    4
}

fn default_cache_capacity() -> usize {
    10_000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            providers: ProviderConfig::default(),
            request_timeout: default_request_timeout(),
            negative_ttl: default_negative_ttl(),
            network_scope_policy: NetworkScopePolicy::default(),
            max_concurrent_enrichments: default_max_concurrent_enrichments(),
            cache_capacity: default_cache_capacity(),
            user_agent: UserAgentConfig::default(),
        }
    }
}

/// The identifier of the AbuseIPDB provider.
pub const ABUSEIPDB_FEATURE: &str = "abuseipdb";
/// The identifier of the CrowdSec provider.
pub const CROWDSEC_FEATURE: &str = "crowdsec";

/// The upstream endpoint of the AbuseIPDB check API.
pub const ABUSEIPDB_DEFAULT_BASE_URL: &str = "https://api.abuseipdb.com/api/v2";
/// The upstream endpoint of the CrowdSec CTI API.
pub const CROWDSEC_DEFAULT_BASE_URL: &str = "https://cti.api.crowdsec.net/v2";

/// The default daily budget of the AbuseIPDB provider.
pub const ABUSEIPDB_DEFAULT_DAILY_QUOTA: u32 = 1_000;
/// The default monthly budget of the CrowdSec provider.
pub const CROWDSEC_DEFAULT_MONTHLY_QUOTA: u32 = 120;
/// The default number of days of reports requested from AbuseIPDB.
pub const ABUSEIPDB_DEFAULT_MAX_AGE_DAYS: u32 = 30;

impl ProviderConfig {
    /// Whether the AbuseIPDB provider is configured and enabled.
    pub fn abuseipdb_enabled(&self) -> bool {
        self.abuseipdb.as_ref().is_some_and(|c| c.enabled)
    }

    /// Whether the CrowdSec provider is configured and enabled.
    pub fn crowdsec_enabled(&self) -> bool {
        self.crowdsec.as_ref().is_some_and(|c| c.enabled)
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
