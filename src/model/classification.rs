//! Verdict model: the three states an assessment can end in.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::model::evidence::{Evidence, ProviderId, Suppression};

/// The outcome of an assessment.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// A conviction rule was satisfied.
    Bad,
    /// Valid evidence exists but no conviction rule was satisfied.
    Suspect,
    /// No usable evidence exists.
    Unknown,
}

/// Why a verdict carries its classification.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictReason {
    /// A conviction rule was satisfied.
    Convicted,
    /// Evidence is present but insufficient.
    EvidencePresent,
    /// Evidence existed but had expired.
    EvidenceExpired,
    /// Providers were consulted and reported nothing.
    NoEvidence,
    /// Nothing was consulted successfully.
    NoCoverage,
}

/// How strongly a provider stated its answer about an address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    /// The provider evaluated this address and returned a verdict.
    ///
    /// A provider that publishes a list evaluated the address against the
    /// list, so an address the list names is evaluated as well.
    Definitive,
    /// The provider was consulted but its statement about this address is weak.
    Partial,
}

/// Per-provider record of who was consulted about an address.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Coverage {
    /// Providers that evaluated the address and returned a verdict.
    #[serde(default)]
    pub definitive: Vec<ProviderId>,
    /// Providers that were consulted but whose statement is weak.
    #[serde(default)]
    pub partial: Vec<ProviderId>,
    /// Providers that failed.
    #[serde(default)]
    pub failed: Vec<(ProviderId, ProviderError)>,
}

impl Coverage {
    /// Whether any provider produced a statement about the address.
    pub fn is_consulted(&self) -> bool {
        !self.definitive.is_empty() || !self.partial.is_empty()
    }

    /// Adds a provider that answered.
    pub fn record_success(&mut self, provider: ProviderId, level: CoverageLevel) {
        let bucket = match level {
            CoverageLevel::Definitive => &mut self.definitive,
            CoverageLevel::Partial => &mut self.partial,
        };
        if !bucket.contains(&provider) {
            bucket.push(provider);
        }
    }

    /// Adds a provider that failed.
    pub fn record_failure(&mut self, provider: ProviderId, error: ProviderError) {
        if !self.failed.iter().any(|(id, _)| *id == provider) {
            self.failed.push((provider, error));
        }
    }
}

/// The verdict for one address.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IpVerdict {
    /// The assessed address.
    pub ip: IpAddr,
    /// The outcome.
    pub classification: Classification,
    /// Why the outcome is what it is.
    pub reason: VerdictReason,
    /// Every valid observation the verdict was derived from.
    ///
    /// The observations of a provider that published a `Safe` suppression are
    /// absent, because that provider withdrew its own claim.
    pub evidence: Vec<Evidence>,
    /// The provider-side suppressions that apply.
    pub suppressions: Vec<(ProviderId, Suppression)>,
    /// Which providers were consulted.
    pub coverage: Coverage,
    /// When the verdict was produced.
    pub assessed_at: OffsetDateTime,
}

/// The inputs of the decision engine.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VerdictInput {
    /// The assessed address.
    pub ip: IpAddr,
    /// The observations to consider.
    pub evidence: Vec<Evidence>,
    /// The suppressions to consider.
    pub suppressions: Vec<(ProviderId, Suppression)>,
    /// The coverage record.
    pub coverage: Coverage,
}

impl VerdictInput {
    /// Creates an input without evidence, suppressions or coverage.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            evidence: Vec::new(),
            suppressions: Vec::new(),
            coverage: Coverage::default(),
        }
    }
}
