//! The decision engine.
//!
//! The verdict is a rule over evidence. The engine is a total function of the
//! evidence set, the suppressions, the coverage record, the configuration and
//! the assessment instant.

pub mod rules;

use std::collections::BTreeSet;

use time::OffsetDateTime;

use crate::config::{Config, NetworkScopePolicy};
use crate::model::{
    Assertion, Classification, Evidence, EvidenceStrength, IpVerdict, Suppression, VerdictInput,
    VerdictReason,
};

/// Classifies an evidence set.
///
/// The function never fails and never panics. The same arguments always produce
/// the same verdict.
pub fn classify(input: &VerdictInput, config: &Config, now: OffsetDateTime) -> IpVerdict {
    let policy = config.network_scope_policy;

    let (valid, expired): (Vec<&Evidence>, Vec<&Evidence>) = input
        .evidence
        .iter()
        .partition(|evidence| evidence.is_valid_at(now));

    let safe = input
        .suppressions
        .iter()
        .any(|(_, suppression)| *suppression == Suppression::Safe);
    let benign = input
        .suppressions
        .iter()
        .any(|(_, suppression)| *suppression == Suppression::Benign);

    let single_source = !safe && !benign && valid.iter().any(|e| convicts_alone(e, policy));
    let corroborated = !safe && count_voting_families(&valid, policy) >= 2;

    let (classification, reason) = if single_source || corroborated {
        (Classification::Bad, VerdictReason::Convicted)
    } else if !valid.is_empty() {
        (Classification::Suspect, VerdictReason::EvidencePresent)
    } else if !expired.is_empty() {
        (Classification::Unknown, VerdictReason::EvidenceExpired)
    } else if input.coverage.is_consulted() {
        (Classification::Unknown, VerdictReason::NoEvidence)
    } else {
        (Classification::Unknown, VerdictReason::NoCoverage)
    };

    IpVerdict {
        ip: input.ip,
        classification,
        reason,
        evidence: valid.into_iter().cloned().collect(),
        suppressions: input.suppressions.clone(),
        coverage: input.coverage.clone(),
        assessed_at: now,
    }
}

/// Whether an observation satisfies the single-source conviction path.
fn convicts_alone(evidence: &Evidence, policy: NetworkScopePolicy) -> bool {
    if evidence.strength != EvidenceStrength::Convicting {
        return false;
    }
    match policy {
        NetworkScopePolicy::CorroborateOnly => {
            evidence.scope.is_exact() && evidence.assertion != Assertion::NetworkControl
        }
        NetworkScopePolicy::Allow => true,
    }
}

/// Whether an observation may add a corroboration vote.
fn votes(evidence: &Evidence, policy: NetworkScopePolicy) -> bool {
    if !matches!(
        evidence.strength,
        EvidenceStrength::Convicting | EvidenceStrength::Corroborating
    ) {
        return false;
    }
    match policy {
        NetworkScopePolicy::CorroborateOnly => {
            (evidence.assertion == Assertion::Attack && evidence.scope.is_exact())
                || evidence.assertion == Assertion::NetworkControl
        }
        NetworkScopePolicy::Allow => true,
    }
}

/// The number of distinct source families that may convict by corroboration.
fn count_voting_families(evidence: &[&Evidence], policy: NetworkScopePolicy) -> usize {
    evidence
        .iter()
        .filter(|e| votes(e, policy))
        .map(|e| e.family.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use time::{Duration, OffsetDateTime};

    use super::classify;
    use crate::config::{Config, NetworkScopePolicy};
    use crate::model::{
        Assertion, Classification, Coverage, CoverageLevel, Evidence, EvidenceStrength, MatchScope,
        ProviderId, SourceFamily, Suppression, ThreatCategory, VerdictInput, VerdictReason,
    };

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    fn evidence(
        provider: ProviderId,
        family: SourceFamily,
        assertion: Assertion,
        strength: EvidenceStrength,
        scope: MatchScope,
    ) -> Evidence {
        Evidence {
            provider,
            family,
            assertion,
            category: ThreatCategory::WebAttack,
            raw_category: None,
            strength,
            scope,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            raw_values: Default::default(),
        }
    }

    fn exact_convicting(provider: &'static str, family: &'static str) -> Evidence {
        evidence(
            ProviderId::new(provider),
            SourceFamily::new(family),
            Assertion::Attack,
            EvidenceStrength::Convicting,
            MatchScope::Exact,
        )
    }

    fn exact_corroborating(provider: &'static str, family: &'static str) -> Evidence {
        evidence(
            ProviderId::new(provider),
            SourceFamily::new(family),
            Assertion::Attack,
            EvidenceStrength::Corroborating,
            MatchScope::Exact,
        )
    }

    fn prefix_network_control(provider: &'static str, family: &'static str) -> Evidence {
        evidence(
            ProviderId::new(provider),
            SourceFamily::new(family),
            Assertion::NetworkControl,
            EvidenceStrength::Convicting,
            MatchScope::Prefix {
                network: "45.32.0.0/16".parse().unwrap(),
            },
        )
    }

    fn input(evidence: Vec<Evidence>) -> VerdictInput {
        VerdictInput {
            ip: IpAddr::from([45, 32, 1, 1]),
            evidence,
            suppressions: Vec::new(),
            coverage: Coverage::default(),
        }
    }

    #[test]
    fn one_convicting_exact_observation_convicts() {
        let verdict = classify(
            &input(vec![exact_convicting("abuseipdb", "abuseipdb")]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn two_observations_of_one_family_do_not_corroborate() {
        let verdict = classify(
            &input(vec![
                exact_corroborating("abuseipdb", "abuseipdb"),
                exact_corroborating("mirror", "abuseipdb"),
            ]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Suspect);
        assert_eq!(verdict.reason, VerdictReason::EvidencePresent);
    }

    #[test]
    fn two_observations_of_two_families_corroborate() {
        let verdict = classify(
            &input(vec![
                exact_corroborating("abuseipdb", "abuseipdb"),
                exact_corroborating("crowdsec", "crowdsec"),
            ]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
    }

    #[test]
    fn a_prefix_observation_never_convicts_alone() {
        let verdict = classify(
            &input(vec![prefix_network_control("spamhaus", "spamhaus")]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Suspect);
    }

    #[test]
    fn a_prefix_attack_observation_never_convicts_alone() {
        let verdict = classify(
            &input(vec![evidence(
                ProviderId::new("spamhaus"),
                SourceFamily::new("spamhaus"),
                Assertion::Attack,
                EvidenceStrength::Convicting,
                MatchScope::Prefix {
                    network: "45.32.0.0/16".parse().unwrap(),
                },
            )]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Suspect);
    }

    #[test]
    fn a_prefix_observation_corroborates_another_family() {
        let verdict = classify(
            &input(vec![
                prefix_network_control("spamhaus", "spamhaus"),
                exact_convicting("abuseipdb", "abuseipdb"),
            ]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
    }

    #[test]
    fn a_safe_suppression_prevents_a_conviction() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("crowdsec"), Suppression::Safe));
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Suspect);
    }

    #[test]
    fn a_benign_suppression_prevents_a_single_source_conviction() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("crowdsec"), Suppression::Benign));
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Suspect);
    }

    #[test]
    fn a_benign_suppression_allows_a_corroborated_conviction() {
        let mut input = input(vec![
            exact_convicting("abuseipdb", "abuseipdb"),
            exact_convicting("crowdsec", "crowdsec"),
        ]);
        input
            .suppressions
            .push((ProviderId::new("crowdsec"), Suppression::Benign));
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Bad);
    }

    #[test]
    fn expired_evidence_contributes_nothing() {
        let mut expired = exact_convicting("abuseipdb", "abuseipdb");
        expired.expires_at = Some(now() - Duration::hours(1));
        let verdict = classify(&input(vec![expired]), &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::EvidenceExpired);
    }

    #[test]
    fn evidence_that_has_not_expired_is_valid() {
        let mut valid = exact_convicting("abuseipdb", "abuseipdb");
        valid.expires_at = Some(now() + Duration::hours(1));
        let verdict = classify(&input(vec![valid]), &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Bad);
    }

    #[test]
    fn a_consulted_provider_without_evidence_yields_no_evidence() {
        let mut input = input(Vec::new());
        input
            .coverage
            .record_success(ProviderId::new("abuseipdb"), CoverageLevel::Definitive);
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoEvidence);
        assert_eq!(verdict.coverage.definitive.len(), 1);
    }

    #[test]
    fn without_any_provider_the_verdict_has_no_coverage() {
        let verdict = classify(&input(Vec::new()), &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoCoverage);
        assert!(verdict.coverage.definitive.is_empty());
        assert!(verdict.coverage.partial.is_empty());
    }

    #[test]
    fn indicative_evidence_never_votes() {
        let indicative = evidence(
            ProviderId::new("abuseipdb"),
            SourceFamily::new("abuseipdb"),
            Assertion::Attack,
            EvidenceStrength::Indicative,
            MatchScope::Exact,
        );
        let corroborating = evidence(
            ProviderId::new("crowdsec"),
            SourceFamily::new("crowdsec"),
            Assertion::Attack,
            EvidenceStrength::Corroborating,
            MatchScope::Exact,
        );
        let verdict = classify(
            &input(vec![indicative, corroborating]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Suspect);
    }

    #[test]
    fn the_network_scope_policy_decides_about_prefix_observations() {
        let evidence = vec![evidence(
            ProviderId::new("spamhaus"),
            SourceFamily::new("spamhaus"),
            Assertion::Attack,
            EvidenceStrength::Convicting,
            MatchScope::Prefix {
                network: "45.32.0.0/16".parse().unwrap(),
            },
        )];
        let config = Config {
            network_scope_policy: NetworkScopePolicy::Allow,
            ..Config::default()
        };
        let verdict = classify(&input(evidence), &config, now());
        assert_eq!(verdict.classification, Classification::Bad);
    }
}
