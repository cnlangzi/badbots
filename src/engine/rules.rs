//! The conviction rules of the supported source families.
//!
//! The thresholds live here, compiled into the engine, because each source
//! publishes its own semantics and a configurable number invites operators to
//! tune a threshold that no measurement supports.

/// The conviction rule of the AbuseIPDB report lineage.
pub mod abuseipdb {
    use crate::model::EvidenceStrength;

    /// The score at which a report convicts on its own.
    pub const CONVICTION_SCORE: u32 = 75;
    /// The score at which a report is a valid signal.
    pub const SUSPICION_SCORE: u32 = 25;
    /// The number of distinct reporters a conviction needs.
    pub const MIN_DISTINCT_USERS: u32 = 2;
    /// The age of the most recent report a conviction needs.
    pub const MAX_REPORT_AGE_DAYS: i64 = 30;

    /// The strength of an AbuseIPDB observation.
    ///
    /// Returns `None` when the observation carries no evidence at all.
    pub fn strength(
        score: u32,
        distinct_users: u32,
        has_inbound_category: bool,
        report_within_window: bool,
    ) -> Option<EvidenceStrength> {
        if !has_inbound_category {
            return None;
        }
        if score >= CONVICTION_SCORE && distinct_users >= MIN_DISTINCT_USERS && report_within_window
        {
            return Some(EvidenceStrength::Convicting);
        }
        if (score >= SUSPICION_SCORE && distinct_users >= MIN_DISTINCT_USERS)
            || (score >= CONVICTION_SCORE && distinct_users >= 1)
        {
            return Some(EvidenceStrength::Indicative);
        }
        None
    }
}

/// The conviction rule of the CrowdSec CTI lineage.
pub mod crowdsec {
    use crate::model::EvidenceStrength;

    /// The reputation value that reports an attacking address.
    pub const REPUTATION_MALICIOUS: &str = "malicious";
    /// The reputation value that reports a weakly suspicious address.
    pub const REPUTATION_SUSPICIOUS: &str = "suspicious";
    /// The reputation value that reports a benign address.
    pub const REPUTATION_BENIGN: &str = "benign";
    /// The reputation value that reports a safe address.
    pub const REPUTATION_SAFE: &str = "safe";
    /// The background noise level that weakens a conviction.
    pub const BACKGROUND_NOISE_HIGH: &str = "high";
    /// The classification that convicts on its own.
    pub const COMMUNITY_BLOCKLIST: &str = "community-blocklist";
    /// The reference that convicts on its own.
    pub const INTELLIGENCE_BLOCKLIST_REFERENCE: &str = "list:crowdsec_intelligence_blocklist";

    /// The inputs of the CrowdSec conviction rule.
    #[derive(Clone, Copy, Debug)]
    pub struct Inputs<'a> {
        /// The reputation the source published.
        pub reputation: &'a str,
        /// Whether a reported behavior has the malicious intent.
        pub has_malicious_behavior: bool,
        /// Whether the address carries a blocklist classification or reference.
        pub has_blocklist_marker: bool,
        /// Whether the source tagged the address as a false positive.
        pub has_false_positive: bool,
        /// The background noise level the source published.
        pub background_noise: &'a str,
    }

    /// The strength of a CrowdSec observation.
    ///
    /// Returns `None` when the observation carries no evidence at all.
    pub fn strength(inputs: Inputs) -> Option<EvidenceStrength> {
        let base = (inputs.reputation == REPUTATION_MALICIOUS && inputs.has_malicious_behavior)
            || inputs.has_blocklist_marker;

        if base {
            let weakened =
                inputs.has_false_positive || inputs.background_noise == BACKGROUND_NOISE_HIGH;
            return Some(if weakened {
                EvidenceStrength::Indicative
            } else {
                EvidenceStrength::Convicting
            });
        }

        if inputs.reputation == REPUTATION_SUSPICIOUS || inputs.reputation == REPUTATION_MALICIOUS {
            return Some(EvidenceStrength::Indicative);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::abuseipdb;
    use crate::model::EvidenceStrength;

    #[test]
    fn abuseipdb_convicts_on_a_strong_recent_report() {
        assert_eq!(
            abuseipdb::strength(100, 5, true, true),
            Some(EvidenceStrength::Convicting)
        );
    }

    #[test]
    fn abuseipdb_does_not_convict_below_the_score_or_user_bar() {
        assert_eq!(
            abuseipdb::strength(60, 5, true, true),
            Some(EvidenceStrength::Indicative)
        );
        assert_eq!(
            abuseipdb::strength(100, 1, true, true),
            Some(EvidenceStrength::Indicative)
        );
    }

    #[test]
    fn abuseipdb_produces_no_evidence_without_an_inbound_category() {
        assert_eq!(abuseipdb::strength(100, 5, false, true), None);
        assert_eq!(abuseipdb::strength(10, 3, true, true), None);
    }
}
