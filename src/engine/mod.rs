//! The decision engine.
//!
//! The verdict is a rule over evidence. The engine is a total function of the
//! evidence set, the suppressions, the coverage record, the configuration and
//! the assessment instant.

pub mod rules;

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;

use crate::config::{Config, EvidencePolicy, NetworkScopePolicy};
use crate::model::{
    Assertion, Classification, Evidence, EvidenceStrength, IpVerdict, ProviderId, Suppression,
    VerdictInput, VerdictReason,
};

/// Classifies an evidence set.
///
/// The policy of the configuration decides the evidence bar. The strict policy
/// convicts on one `Convicting` observation that satisfies the single-source
/// condition, or on two source families that corroborate each other. The
/// lenient policy convicts on every valid observation that no provider
/// withdrew.
///
/// The function never fails and never panics. The same arguments always produce
/// the same verdict.
pub fn classify(input: &VerdictInput, config: &Config, now: OffsetDateTime) -> IpVerdict {
    let suppressions = suppressions_by_provider(&input.suppressions);

    let (valid, expired): (Vec<&Evidence>, Vec<&Evidence>) = input
        .evidence
        .iter()
        .filter(|evidence| suppressions.get(&evidence.provider) != Some(&Suppression::Safe))
        .partition(|evidence| evidence.is_valid_at(now));

    let (classification, reason) = if satisfies_policy(&valid, &suppressions, config) {
        (Classification::Bad, VerdictReason::Convicted)
    } else if !valid.is_empty() {
        (Classification::Unknown, VerdictReason::InsufficientEvidence)
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

/// Whether the valid observations satisfy the evidence bar of the policy.
///
/// A `Safe` suppression is already accounted for: the observations of the
/// provider that published it never reach the valid set.
fn satisfies_policy(
    valid: &[&Evidence],
    suppressions: &BTreeMap<ProviderId, Suppression>,
    config: &Config,
) -> bool {
    match config.evidence_policy {
        EvidencePolicy::Strict => {
            let single_source = valid.iter().any(|evidence| {
                suppressions.get(&evidence.provider) != Some(&Suppression::Benign)
                    && convicts_alone(evidence, config.network_scope_policy)
            });
            let corroborated = count_voting_families(valid, config.network_scope_policy) >= 2;
            single_source || corroborated
        }
        EvidencePolicy::Lenient => valid
            .iter()
            .any(|evidence| suppressions.get(&evidence.provider) != Some(&Suppression::Benign)),
    }
}

/// The suppression that speaks for each provider.
///
/// A suppression constrains the evidence of the provider that published it and
/// nothing else. A provider that published more than one suppression is treated
/// as the strongest of them, because `Safe` withdraws the evidence entirely.
fn suppressions_by_provider(
    suppressions: &[(ProviderId, Suppression)],
) -> BTreeMap<ProviderId, Suppression> {
    let mut by_provider: BTreeMap<ProviderId, Suppression> = BTreeMap::new();
    for (provider, suppression) in suppressions {
        let published = by_provider.entry(provider.clone()).or_insert(*suppression);
        if *suppression == Suppression::Safe {
            *published = Suppression::Safe;
        }
    }
    by_provider
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

    use super::{classify, count_voting_families};
    use crate::config::{Config, EvidencePolicy, NetworkScopePolicy};
    use crate::model::{
        Assertion, Classification, Coverage, CoverageLevel, Evidence, EvidenceStrength, IpVerdict,
        MatchScope, ProviderId, SourceFamily, Suppression, ThreatCategory, VerdictInput,
        VerdictReason,
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
            upstream_category: None,
            strength,
            scope,
            observed_at: None,
            published_at: None,
            retrieved_at: None,
            expires_at: None,
            observation_window: None,
            count: None,
            upstream_values: Default::default(),
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

    /// A configuration with the evidence policy the test asks for.
    fn policy(policy: EvidencePolicy) -> Config {
        Config {
            evidence_policy: policy,
            ..Config::default()
        }
    }

    /// An observation that only signals doubt.
    fn exact_indicative(provider: &'static str, family: &'static str) -> Evidence {
        evidence(
            ProviderId::new(provider),
            SourceFamily::new(family),
            Assertion::Attack,
            EvidenceStrength::Indicative,
            MatchScope::Exact,
        )
    }

    /// A prefix-scoped observation about an attack.
    fn prefix_attack(provider: &'static str, family: &'static str) -> Evidence {
        evidence(
            ProviderId::new(provider),
            SourceFamily::new(family),
            Assertion::Attack,
            EvidenceStrength::Convicting,
            MatchScope::Prefix {
                network: "45.32.0.0/16".parse().unwrap(),
            },
        )
    }

    /// The number of source families the verdict may convict by.
    fn voting_families(verdict: &IpVerdict, config: &Config) -> usize {
        let evidence: Vec<&Evidence> = verdict.evidence.iter().collect();
        count_voting_families(&evidence, config.network_scope_policy)
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
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
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
        assert_eq!(verdict.classification, Classification::Unknown);
    }

    #[test]
    fn a_prefix_attack_observation_never_convicts_alone() {
        let verdict = classify(
            &input(vec![prefix_attack("spamhaus", "spamhaus")]),
            &Config::default(),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Unknown);
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
    fn a_safe_suppression_of_another_provider_does_not_prevent_a_conviction() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("crowdsec"), Suppression::Safe));
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn a_benign_suppression_of_another_provider_does_not_prevent_a_conviction() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("crowdsec"), Suppression::Benign));
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn evidence_without_a_suppression_may_convict_alone() {
        let config = Config::default();
        let verdict = classify(
            &input(vec![exact_convicting("abuseipdb", "abuseipdb")]),
            &config,
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(voting_families(&verdict, &config), 1);
    }

    #[test]
    fn benign_evidence_may_corroborate_but_not_convict_alone() {
        let config = Config::default();
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));
        let verdict = classify(&input, &config, now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
        assert_eq!(voting_families(&verdict, &config), 1);
    }

    #[test]
    fn benign_evidence_still_corroborates() {
        let config = Config::default();
        let mut input = input(vec![
            exact_corroborating("abuseipdb", "abuseipdb"),
            exact_corroborating("crowdsec", "crowdsec"),
        ]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));
        let verdict = classify(&input, &config, now());
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
        assert_eq!(voting_families(&verdict, &config), 2);
    }

    #[test]
    fn safe_evidence_is_void() {
        let config = Config::default();
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Safe));
        input
            .coverage
            .record_success(ProviderId::new("abuseipdb"), CoverageLevel::Definitive);
        let verdict = classify(&input, &config, now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoEvidence);
        assert!(verdict.evidence.is_empty());
        assert_eq!(
            verdict.suppressions,
            vec![(ProviderId::new("abuseipdb"), Suppression::Safe)]
        );
        assert_eq!(voting_families(&verdict, &config), 0);
    }

    #[test]
    fn a_safe_suppression_voids_an_expired_observation() {
        let mut expired = exact_convicting("abuseipdb", "abuseipdb");
        expired.expires_at = Some(now() - Duration::hours(1));
        let mut input = input(vec![expired]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Safe));
        input
            .coverage
            .record_success(ProviderId::new("abuseipdb"), CoverageLevel::Definitive);
        let verdict = classify(&input, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoEvidence);
    }

    #[test]
    fn the_strongest_suppression_of_a_provider_wins() {
        let mut safe_first = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        safe_first
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Safe));
        safe_first
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));
        let verdict = classify(&safe_first, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert!(verdict.evidence.is_empty());

        let mut benign_first = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        benign_first
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));
        benign_first
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Safe));
        let verdict = classify(&benign_first, &Config::default(), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert!(verdict.evidence.is_empty());
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
        assert_eq!(verdict.classification, Classification::Unknown);
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

    #[test]
    fn an_indicative_observation_is_insufficient_under_the_strict_policy() {
        let verdict = classify(
            &input(vec![exact_indicative("abuseipdb", "abuseipdb")]),
            &policy(EvidencePolicy::Strict),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
    }

    #[test]
    fn an_indicative_observation_convicts_under_the_lenient_policy() {
        let verdict = classify(
            &input(vec![exact_indicative("abuseipdb", "abuseipdb")]),
            &policy(EvidencePolicy::Lenient),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn a_prefix_observation_convicts_under_the_lenient_policy() {
        let verdict = classify(
            &input(vec![prefix_attack("spamhaus", "spamhaus")]),
            &policy(EvidencePolicy::Lenient),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn the_network_scope_policy_does_not_apply_to_the_lenient_policy() {
        let evidence = vec![prefix_attack("spamhaus", "spamhaus")];

        let strict = classify(
            &input(evidence.clone()),
            &policy(EvidencePolicy::Strict),
            now(),
        );
        assert_eq!(strict.classification, Classification::Unknown);
        assert_eq!(strict.reason, VerdictReason::InsufficientEvidence);

        let lenient = classify(&input(evidence), &policy(EvidencePolicy::Lenient), now());
        assert_eq!(lenient.classification, Classification::Bad);
    }

    #[test]
    fn the_lenient_policy_accepts_a_prefix_observation_under_every_scope_policy() {
        for scope in [
            NetworkScopePolicy::CorroborateOnly,
            NetworkScopePolicy::Allow,
        ] {
            let config = Config {
                evidence_policy: EvidencePolicy::Lenient,
                network_scope_policy: scope,
                ..Config::default()
            };
            let verdict = classify(
                &input(vec![prefix_attack("spamhaus", "spamhaus")]),
                &config,
                now(),
            );
            assert_eq!(verdict.classification, Classification::Bad);
        }
    }

    #[test]
    fn a_benign_suppression_alone_is_insufficient_under_the_lenient_policy() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));

        let verdict = classify(&input, &policy(EvidencePolicy::Lenient), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::InsufficientEvidence);
    }

    #[test]
    fn a_benign_suppression_coexists_with_another_family_under_the_lenient_policy() {
        let mut input = input(vec![
            exact_convicting("abuseipdb", "abuseipdb"),
            exact_convicting("crowdsec", "crowdsec"),
        ]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Benign));

        let verdict = classify(&input, &policy(EvidencePolicy::Lenient), now());
        assert_eq!(verdict.classification, Classification::Bad);
        assert_eq!(verdict.reason, VerdictReason::Convicted);
    }

    #[test]
    fn a_safe_suppression_voids_the_evidence_under_the_lenient_policy() {
        let mut input = input(vec![exact_convicting("abuseipdb", "abuseipdb")]);
        input
            .suppressions
            .push((ProviderId::new("abuseipdb"), Suppression::Safe));
        input
            .coverage
            .record_success(ProviderId::new("abuseipdb"), CoverageLevel::Definitive);

        let verdict = classify(&input, &policy(EvidencePolicy::Lenient), now());
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::NoEvidence);
        assert!(verdict.evidence.is_empty());
    }

    #[test]
    fn expired_evidence_contributes_nothing_under_the_lenient_policy() {
        let mut expired = exact_indicative("abuseipdb", "abuseipdb");
        expired.expires_at = Some(now() - Duration::hours(1));

        let verdict = classify(
            &input(vec![expired]),
            &policy(EvidencePolicy::Lenient),
            now(),
        );
        assert_eq!(verdict.classification, Classification::Unknown);
        assert_eq!(verdict.reason, VerdictReason::EvidenceExpired);
    }
}
