//! Evidence model: what a source claims about an address.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Identifies a provider implementation.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProviderId(Cow<'static, str>);

impl ProviderId {
    /// The AbuseIPDB check provider.
    pub const ABUSEIPDB: Self = Self(Cow::Borrowed("abuseipdb"));
    /// The CrowdSec CTI provider.
    pub const CROWDSEC: Self = Self(Cow::Borrowed("crowdsec"));
    /// The Spamhaus DROP list provider.
    pub const SPAMHAUS: Self = Self(Cow::Borrowed("spamhaus"));
    /// The Blocklist.de per-address query provider.
    pub const BLOCKLIST_DE: Self = Self(Cow::Borrowed("blocklist_de"));
    /// The Blocklist.de service list provider.
    pub const BLOCKLIST_DE_LISTS: Self = Self(Cow::Borrowed("blocklist_de_lists"));
    /// The DShield list provider.
    pub const DSHIELD: Self = Self(Cow::Borrowed("dshield"));

    /// Creates an identifier for a provider.
    pub fn new(id: impl Into<Cow<'static, str>>) -> Self {
        Self(id.into())
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProviderId({})", self.as_str())
    }
}

/// Identifies the upstream data lineage an observation belongs to.
///
/// Two observations of the same family count as one vote.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceFamily(Cow<'static, str>);

impl SourceFamily {
    /// The AbuseIPDB report lineage.
    pub const ABUSEIPDB: Self = Self(Cow::Borrowed("abuseipdb"));
    /// The CrowdSec CTI lineage.
    pub const CROWDSEC: Self = Self(Cow::Borrowed("crowdsec"));
    /// The Spamhaus DROP lineage.
    pub const SPAMHAUS: Self = Self(Cow::Borrowed("spamhaus"));
    /// The Blocklist.de lineage.
    pub const BLOCKLIST_DE: Self = Self(Cow::Borrowed("blocklist_de"));
    /// The DShield lineage.
    pub const DSHIELD: Self = Self(Cow::Borrowed("dshield"));

    /// Creates a family identifier.
    pub fn new(family: impl Into<Cow<'static, str>>) -> Self {
        Self(family.into())
    }

    /// Returns the family as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SourceFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceFamily({})", self.as_str())
    }
}

/// What a source claims about an address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {
    /// The source claims this specific address committed an attack.
    Attack,
    /// The source claims this address space is controlled by criminals.
    NetworkControl,
    /// The source observed scanning or probing.
    Reconnaissance,
    /// The source observed abuse such as spam or denial of service.
    Abuse,
    /// The source observed crawling or scraping.
    Scraping,
}

impl Assertion {
    /// Whether the assertion belongs to the inbound attack set.
    ///
    /// The inbound attack set covers the activity that is relevant for traffic
    /// arriving at a web application, reverse proxy, WAF or CDN.
    pub fn is_inbound_attack(self) -> bool {
        matches!(self, Assertion::Attack)
    }
}

/// The intent a source assigns to a reported behavior.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorIntent {
    /// The behavior describes an attack.
    Malicious,
    /// The behavior describes scanning or probing.
    Reconnaissance,
    /// The behavior describes abuse.
    Abusive,
    /// The behavior describes crawling.
    Scraping,
    /// The behavior does not fit a known intent.
    Anomalous,
}

/// The kind of activity a source reports.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// An attack against a web application.
    WebAttack,
    /// Password guessing against a service.
    BruteForce,
    /// Credential replay across services.
    CredentialStuffing,
    /// Scanning or probing.
    Scanner,
    /// Distributed denial of service.
    Ddos,
    /// Spam abuse.
    SpamAbuse,
    /// Botnet or malware activity.
    BotnetOrMalware,
    /// Malicious network or hosting range.
    MaliciousNetwork,
    /// Abuse that fits no narrower category.
    GenericAbuse,
}

/// How far an observation may carry the verdict.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    /// The source's own conviction rule is satisfied; the source may convict alone.
    Convicting,
    /// The source's conviction rule is satisfied; the source may only add a vote.
    Corroborating,
    /// A valid signal below the source's conviction bar.
    Indicative,
}

/// What the observation applies to.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchScope {
    /// The observation is about this exact address.
    Exact,
    /// The observation is about a network the address belongs to.
    Prefix {
        /// The network the observation covers.
        network: IpNet,
    },
}

impl MatchScope {
    /// Whether the scope is the exact address.
    pub fn is_exact(&self) -> bool {
        matches!(self, MatchScope::Exact)
    }

    /// Whether the scope is a network.
    pub fn is_prefix(&self) -> bool {
        matches!(self, MatchScope::Prefix { .. })
    }

    /// The network of a prefix scope.
    pub fn network(&self) -> Option<IpNet> {
        match self {
            MatchScope::Exact => None,
            MatchScope::Prefix { network } => Some(*network),
        }
    }
}

/// A provider-side statement that an address should not be treated as hostile.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suppression {
    /// A hard suppression: prevents `Bad` outright.
    Safe,
    /// A weak suppression: prevents single-source conviction but allows
    /// conviction by corroboration.
    Benign,
}

/// The interval in which an activity was observed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ObservationWindow {
    /// Start of the half-open interval.
    pub start: OffsetDateTime,
    /// End of the half-open interval.
    pub end: OffsetDateTime,
}

/// A single observation about an address.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Evidence {
    /// The provider that produced the observation.
    pub provider: ProviderId,
    /// The upstream data lineage the observation belongs to.
    pub family: SourceFamily,
    /// What the source claims.
    pub assertion: Assertion,
    /// The kind of activity the source reports.
    pub category: ThreatCategory,
    /// The upstream category label, when the source publishes one.
    pub raw_category: Option<String>,
    /// How far the observation may carry the verdict.
    pub strength: EvidenceStrength,
    /// What the observation applies to.
    pub scope: MatchScope,
    /// When the activity was observed.
    pub observed_at: Option<OffsetDateTime>,
    /// When the source published the observation.
    pub published_at: Option<OffsetDateTime>,
    /// When the observation was fetched from the source.
    pub retrieved_at: Option<OffsetDateTime>,
    /// When the observation stops being usable.
    pub expires_at: Option<OffsetDateTime>,
    /// The interval the activity was observed in, for sources that report a period.
    pub observation_window: Option<ObservationWindow>,
    /// The number of events the source counted.
    pub count: Option<u32>,
    /// The upstream values the observation was derived from.
    pub raw_values: BTreeMap<String, String>,
}

impl Evidence {
    /// Whether the observation is still usable at `now`.
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        match self.expires_at {
            Some(expiry) => expiry > now,
            None => true,
        }
    }
}
