//! The provider interfaces and the values they produce.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::model::{CoverageLevel, Evidence, IpVerdict, ProviderId, SourceFamily, Suppression};

pub mod lookup;

#[cfg(feature = "abuseipdb")]
pub mod abuseipdb;
#[cfg(feature = "crowdsec")]
pub mod crowdsec;

/// What a provider is allowed to do with its observations.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    /// The provider may convict on its own.
    Primary,
    /// The provider only ever corroborates.
    Corroborating,
    /// The provider never produces evidence.
    ContextOnly,
}

/// The health of one provider between lookups.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProviderHealth {
    /// The last attempt.
    pub last_attempt: Option<OffsetDateTime>,
    /// The last successful attempt.
    pub last_success: Option<OffsetDateTime>,
    /// The last failure.
    pub last_error: Option<ProviderError>,
}

/// The answer of a lookup provider about one address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderVerdict {
    /// The provider that answered.
    pub provider: ProviderId,
    /// The upstream data lineage of the answer.
    pub family: SourceFamily,
    /// How strongly the provider stated its answer.
    pub coverage: CoverageLevel,
    /// The observations the provider produced.
    pub evidence: Vec<Evidence>,
    /// The suppression the provider published, when it published one.
    pub suppression: Option<Suppression>,
    /// The instant the answer stops being usable.
    pub expires_at: Option<OffsetDateTime>,
}

impl ProviderVerdict {
    /// Creates a verdict without evidence and without suppression.
    pub fn empty(provider: ProviderId, family: SourceFamily, coverage: CoverageLevel) -> Self {
        Self {
            provider,
            family,
            coverage,
            evidence: Vec::new(),
            suppression: None,
            expires_at: None,
        }
    }
}

/// A snapshot of a published list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeedSnapshot {
    /// The provider that published the list.
    pub provider: ProviderId,
    /// The upstream data lineage of the list.
    pub family: SourceFamily,
    /// When the list was published.
    pub published_at: Option<OffsetDateTime>,
    /// When the list was fetched.
    pub retrieved_at: OffsetDateTime,
    /// When the list stops being usable.
    pub expires_at: Option<OffsetDateTime>,
    /// The attribution the upstream asks for.
    pub attribution: String,
    /// The header lines of the published list.
    pub header_lines: Vec<String>,
    /// The entries of the list.
    pub entries: Vec<Evidence>,
}

/// A provider that is asked about one address at a time.
#[async_trait]
pub trait LookupProvider: Send + Sync {
    /// The identifier of the provider.
    fn id(&self) -> ProviderId;
    /// The upstream data lineage of the provider.
    fn family(&self) -> SourceFamily;
    /// What the provider is allowed to do with its observations.
    fn capability(&self) -> ProviderCapability;
    /// Looks the address up.
    async fn lookup(&self, ip: IpAddr) -> Result<ProviderVerdict, ProviderError>;
}

/// A provider that publishes a list of addresses.
#[async_trait]
pub trait FeedProvider: Send + Sync {
    /// The identifier of the provider.
    fn id(&self) -> ProviderId;
    /// The upstream data lineage of the provider.
    fn family(&self) -> SourceFamily;
    /// What the provider is allowed to do with its observations.
    fn capability(&self) -> ProviderCapability;
    /// The shortest interval between two refreshes.
    fn min_refresh_interval(&self) -> Duration;
    /// Fetches the published list.
    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError>;
}

/// The outcome of one provider lookup.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderOutcome {
    /// The provider that was asked.
    pub provider: ProviderId,
    /// The answer, or the reason there is none.
    pub result: Result<ProviderVerdict, ProviderError>,
}

/// The report of one enrichment run.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnrichmentReport {
    /// The assessed address.
    pub ip: IpAddr,
    /// The verdict the evidence produced.
    pub verdict: IpVerdict,
    /// The outcome of every provider that was asked.
    pub outcomes: Vec<ProviderOutcome>,
}

/// The result of one feed refresh.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FeedRefreshResult {
    /// The provider that was asked.
    pub provider: ProviderId,
    /// The snapshot, or the reason there is none.
    pub result: Result<FeedSnapshot, ProviderError>,
}

/// The report of a feed refresh run.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FeedRefreshReport {
    /// The result of every provider that was asked.
    pub results: Vec<FeedRefreshResult>,
}

/// The health of one provider.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProviderStatus {
    /// The provider.
    pub provider: ProviderId,
    /// The upstream data lineage of the provider.
    pub family: SourceFamily,
    /// What the provider is allowed to do with its observations.
    pub capability: ProviderCapability,
    /// Whether the provider is queried.
    pub enabled: bool,
    /// The last successful attempt.
    pub last_success: Option<OffsetDateTime>,
    /// The last attempt.
    pub last_attempt: Option<OffsetDateTime>,
    /// The last failure.
    pub last_error: Option<ProviderError>,
    /// The number of lookups spent in the current budget window.
    pub budget_used: Option<u32>,
    /// The budget of the current window.
    pub budget_limit: Option<u32>,
}
