//! The provider interfaces and the values they produce.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::model::{CoverageLevel, Evidence, ProviderId, SourceFamily, Suppression};

pub mod lookup;
pub mod services;

#[cfg(feature = "abuseipdb")]
pub mod abuseipdb;
#[cfg(feature = "blocklist_de")]
pub mod blocklist_de;
#[cfg(feature = "crowdsec")]
pub mod crowdsec;
#[cfg(feature = "dshield")]
pub mod dshield;
#[cfg(feature = "spamhaus")]
pub mod spamhaus;

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

/// How expensive a lookup of a provider is.
///
/// The classes are ordered from the cheapest to the most expensive one. The
/// lenient policy asks the providers in that order and stops at the first hit,
/// so a provider states its own price.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCost {
    /// The lookup costs nothing.
    Free,
    /// The lookup is cheap.
    Low,
    /// The lookup costs a moderate amount.
    Medium,
    /// The lookup is expensive.
    High,
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

/// What a lookup provider found about one address.
///
/// A finding is a statement of a provider, not a conclusion about the address.
/// The engine derives the conclusion from the findings of every provider.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ProviderFinding {
    /// The provider that answered.
    ///
    /// The engine takes the identity of a provider from the provider itself,
    /// so this field is informational: it names the provider that produced the
    /// finding, and it is never trusted.
    pub provider: ProviderId,
    /// How strongly the provider stated its answer.
    pub coverage: CoverageLevel,
    /// The observations the provider produced.
    pub evidence: Vec<Evidence>,
    /// The suppression the provider published, when it published one.
    pub suppression: Option<Suppression>,
    /// The instant the answer stops being usable.
    pub expires_at: Option<OffsetDateTime>,
}

impl ProviderFinding {
    /// Creates a finding without evidence and without suppression.
    pub fn empty(provider: ProviderId, coverage: CoverageLevel) -> Self {
        Self {
            provider,
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
    ///
    /// The identifier is the key a suppression is matched against, so the
    /// engine takes it from here rather than from the observations themselves.
    fn id(&self) -> ProviderId;
    /// The upstream data lineage of the provider.
    ///
    /// The lineage decides which observations corroborate each other, so the
    /// engine takes it from here rather than from the observations themselves.
    fn family(&self) -> SourceFamily;
    /// What the provider is allowed to do with its observations.
    fn capability(&self) -> ProviderCapability;
    /// How expensive a lookup of the provider is.
    ///
    /// The lenient policy consults the providers from the cheapest to the most
    /// expensive one and stops at the first hit, so the price of a provider
    /// decides where it is asked. The method has no default, because a provider
    /// that silently inherited a price class would sit in the wrong position of
    /// the order without anyone noticing.
    fn cost(&self) -> ProviderCost;
    /// Looks the address up.
    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError>;
}

/// A lookup provider behind a shared handle.
///
/// A registered provider may be handed over as a shared handle.
#[async_trait]
impl<T: LookupProvider + ?Sized> LookupProvider for Arc<T> {
    fn id(&self) -> ProviderId {
        (**self).id()
    }

    fn family(&self) -> SourceFamily {
        (**self).family()
    }

    fn capability(&self) -> ProviderCapability {
        (**self).capability()
    }

    fn cost(&self) -> ProviderCost {
        (**self).cost()
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        (**self).lookup(ip).await
    }
}

/// A provider that publishes a list of addresses.
///
/// An observation about an exact address carries that address in its upstream
/// values under the key `address`, because the index resolves an address to its
/// observations from the snapshot alone.
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

/// A feed provider behind a shared handle.
///
/// A registered provider may be handed over as a shared handle.
#[async_trait]
impl<T: FeedProvider + ?Sized> FeedProvider for Arc<T> {
    fn id(&self) -> ProviderId {
        (**self).id()
    }

    fn family(&self) -> SourceFamily {
        (**self).family()
    }

    fn capability(&self) -> ProviderCapability {
        (**self).capability()
    }

    fn min_refresh_interval(&self) -> Duration {
        (**self).min_refresh_interval()
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        (**self).fetch().await
    }
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
    /// The number of lookups spent in the current quota window.
    pub quota_used: Option<u32>,
    /// The quota of the current window.
    pub quota_limit: Option<u32>,
    /// The number of entries of the loaded list.
    pub entries: Option<u32>,
    /// The publication time of the loaded list.
    pub published_at: Option<OffsetDateTime>,
    /// The earliest instant at which the list may be fetched again.
    pub next_refresh_at: Option<OffsetDateTime>,
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use super::{LookupProvider, ProviderCapability, ProviderCost, ProviderFinding};
    use crate::error::ProviderError;
    use crate::model::{CoverageLevel, ProviderId, SourceFamily};

    /// A provider that states its own price.
    struct Priced;

    #[async_trait::async_trait]
    impl LookupProvider for Priced {
        fn id(&self) -> ProviderId {
            ProviderId::new("priced")
        }

        fn family(&self) -> SourceFamily {
            SourceFamily::new("priced")
        }

        fn capability(&self) -> ProviderCapability {
            ProviderCapability::Corroborating
        }

        fn cost(&self) -> ProviderCost {
            ProviderCost::High
        }

        async fn lookup(&self, _ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
            Ok(ProviderFinding::empty(self.id(), CoverageLevel::Partial))
        }
    }

    #[test]
    fn a_shared_handle_forwards_the_cost_of_the_provider() {
        let provider: Arc<dyn LookupProvider> = Arc::new(Priced);

        assert_eq!(provider.cost(), ProviderCost::High);
    }
}
