//! The CrowdSec CTI provider.
//!
//! The upstream publishes a reputation, the behaviors it observed, the
//! classifications it assigned and the references it links the address to. The
//! key is sent in the `x-api-key` header.
//!
//! The provider is compiled in by the `crowdsec` crate feature. It expects an
//! API key, which the host supplies through the `api_key` field of
//! [`CrowdSecConfig`](crate::config::CrowdSecConfig), the `crowdsec_api_key`
//! builder method or the `BADBOTS_CROWDSEC_API_KEY` environment variable. A
//! provider that is enabled without a key is reported as
//! [`ConfigError::MissingApiKey`](crate::ConfigError::MissingApiKey) when the
//! library is built.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use crate::engine::rules;
use crate::error::ProviderError;
use crate::model::{
    Assertion, BehaviorIntent, CoverageLevel, Evidence, MatchScope, ObservationWindow, ProviderId,
    SourceFamily, Suppression, ThreatCategory,
};
use crate::provider::lookup::{ProviderRuntime, parse_body};
use crate::provider::{LookupProvider, ProviderCapability, ProviderCost, ProviderFinding};
use crate::secret::ApiKey;

/// The number of days a positive result stays usable.
pub const VALIDITY_DAYS: i64 = 90;

/// The compiled-in behavior intent table.
pub fn default_intents() -> &'static BTreeMap<String, BehaviorIntent> {
    static TABLE: OnceLock<BTreeMap<String, BehaviorIntent>> = OnceLock::new();
    TABLE.get_or_init(|| {
        [
            ("exploit", BehaviorIntent::Malicious),
            ("bruteforce", BehaviorIntent::Malicious),
            ("brute_force", BehaviorIntent::Malicious),
            ("flood", BehaviorIntent::Malicious),
            ("dos", BehaviorIntent::Malicious),
            ("proxy", BehaviorIntent::Malicious),
            ("sqli", BehaviorIntent::Malicious),
            ("sql_injection", BehaviorIntent::Malicious),
            ("idor", BehaviorIntent::Malicious),
            ("rce", BehaviorIntent::Malicious),
            ("spoof", BehaviorIntent::Malicious),
            ("lateral", BehaviorIntent::Malicious),
            ("scan", BehaviorIntent::Reconnaissance),
            ("spam", BehaviorIntent::Abusive),
            ("crawl", BehaviorIntent::Scraping),
            ("scraping", BehaviorIntent::Scraping),
            ("anomaly", BehaviorIntent::Anomalous),
        ]
        .into_iter()
        .map(|(name, intent)| (name.to_string(), intent))
        .collect()
    })
}

/// The intent of a reported behavior.
pub fn intent_of(
    name: &str,
    overrides: &BTreeMap<String, BehaviorIntent>,
) -> Option<BehaviorIntent> {
    if let Some(intent) = overrides.get(name) {
        return Some(*intent);
    }
    let tail = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
    if let Some(intent) = overrides.get(&tail) {
        return Some(*intent);
    }
    default_intents().get(&tail).copied()
}

/// The threat category a reported behavior belongs to.
pub fn threat_category(name: &str) -> ThreatCategory {
    let tail = name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase();
    match tail.as_str() {
        "exploit" | "sqli" | "sql_injection" | "idor" | "rce" => ThreatCategory::WebAttack,
        "bruteforce" | "brute_force" => ThreatCategory::BruteForce,
        "scan" => ThreatCategory::Scanner,
        "spam" => ThreatCategory::SpamAbuse,
        "crawl" | "scraping" => ThreatCategory::GenericAbuse,
        "flood" | "dos" => ThreatCategory::Ddos,
        "lateral" => ThreatCategory::BotnetOrMalware,
        _ => ThreatCategory::GenericAbuse,
    }
}

/// The assertion a reported behavior belongs to.
pub fn assertion_of(intent: BehaviorIntent) -> Assertion {
    match intent {
        BehaviorIntent::Malicious => Assertion::Attack,
        BehaviorIntent::Reconnaissance => Assertion::Reconnaissance,
        BehaviorIntent::Abusive => Assertion::Abuse,
        BehaviorIntent::Scraping => Assertion::Scraping,
        BehaviorIntent::Anomalous => Assertion::Abuse,
    }
}

/// The CrowdSec CTI provider.
pub struct CrowdSecProvider {
    api_key: ApiKey,
    base_url: String,
    behavior_intents: BTreeMap<String, BehaviorIntent>,
    runtime: Arc<ProviderRuntime>,
}

impl CrowdSecProvider {
    /// Creates a provider.
    pub fn new(
        api_key: ApiKey,
        base_url: impl Into<String>,
        behavior_intents: BTreeMap<String, BehaviorIntent>,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            api_key,
            base_url: base_url.into(),
            behavior_intents,
            runtime,
        }
    }
}

#[async_trait]
impl LookupProvider for CrowdSecProvider {
    fn id(&self) -> ProviderId {
        ProviderId::CROWDSEC
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::CROWDSEC
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Primary
    }

    fn cost(&self) -> ProviderCost {
        ProviderCost::High
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderFinding, ProviderError> {
        let now = self.runtime.clock().now();
        let url = format!("{}/smoke/{ip}", self.base_url.trim_end_matches('/'));
        let request = self
            .runtime
            .client()
            .get(url)
            .header("x-api-key", self.api_key.expose())
            .header("Accept", "application/json");

        let response = self.runtime.send(request, now).await?;
        let body = self.runtime.read_body(response).await?;
        let parsed: SmokeResponse = parse_body(&body)?;

        let reputation = parsed.reputation.unwrap_or_else(|| "unknown".to_string());
        let background_noise = parsed.background_noise.clone().unwrap_or_default();

        let false_positives = parsed
            .classifications
            .as_ref()
            .and_then(|c| c.false_positives.clone())
            .unwrap_or_default();
        let classifications = parsed
            .classifications
            .as_ref()
            .and_then(|c| c.classifications.clone())
            .unwrap_or_default();
        let references = parsed.references.clone().unwrap_or_default();
        let behaviors = parsed.behaviors.clone().unwrap_or_default();

        let has_malicious_behavior = behaviors.iter().any(|behavior| {
            behavior
                .name
                .as_deref()
                .and_then(|name| intent_of(name, &self.behavior_intents))
                .is_some_and(|intent| intent == BehaviorIntent::Malicious)
        });
        let has_blocklist_marker = classifications
            .iter()
            .any(|entry| entry == rules::crowdsec::COMMUNITY_BLOCKLIST)
            || references
                .iter()
                .any(|entry| entry == rules::crowdsec::INTELLIGENCE_BLOCKLIST_REFERENCE);

        let strength = rules::crowdsec::strength(rules::crowdsec::Inputs {
            reputation: &reputation,
            has_malicious_behavior,
            has_blocklist_marker,
            has_false_positive: !false_positives.is_empty(),
            background_noise: &background_noise,
        });

        let mut suppression: Option<Suppression> = None;
        if reputation == rules::crowdsec::REPUTATION_BENIGN {
            suppression = Some(Suppression::Benign);
        }
        if reputation == rules::crowdsec::REPUTATION_SAFE || !false_positives.is_empty() {
            suppression = Some(Suppression::Safe);
        }

        let suppressive_reputation = reputation == rules::crowdsec::REPUTATION_BENIGN
            || reputation == rules::crowdsec::REPUTATION_SAFE;

        let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
        upstream_values.insert("reputation".to_string(), reputation.clone());
        if let Some(score) = parsed.reputation_score {
            upstream_values.insert("reputation_score".to_string(), score.to_string());
        }
        upstream_values.insert("background_noise".to_string(), background_noise.clone());
        if let Some(score) = parsed.background_noise_score {
            upstream_values.insert("background_noise_score".to_string(), score.to_string());
        }
        if !false_positives.is_empty() {
            upstream_values.insert("false_positives".to_string(), false_positives.join(","));
        }
        if !classifications.is_empty() {
            upstream_values.insert("classifications".to_string(), classifications.join(","));
        }
        if !references.is_empty() {
            upstream_values.insert("references".to_string(), references.join(","));
        }
        if !behaviors.is_empty() {
            upstream_values.insert(
                "behaviors".to_string(),
                behaviors
                    .iter()
                    .filter_map(|behavior| behavior.name.clone())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(history) = &parsed.history
            && let Some(first_seen) = &history.first_seen
        {
            upstream_values.insert("first_seen".to_string(), first_seen.clone());
        }
        if let Some(history) = &parsed.history
            && let Some(last_seen) = &history.last_seen
        {
            upstream_values.insert("last_seen".to_string(), last_seen.clone());
        }
        if let Some(scores) = &parsed.scores {
            upstream_values.insert(
                "scores".to_string(),
                serde_json::to_string(scores).unwrap_or_default(),
            );
        }

        let last_seen = parsed
            .history
            .as_ref()
            .and_then(|history| history.last_seen.as_deref())
            .and_then(parse_timestamp);

        let Some(strength) = strength else {
            return Ok(ProviderFinding {
                provider: ProviderId::CROWDSEC,
                coverage: CoverageLevel::Definitive,
                evidence: Vec::new(),
                suppression,
                expires_at: None,
            });
        };

        if suppressive_reputation {
            return Ok(ProviderFinding {
                provider: ProviderId::CROWDSEC,
                coverage: CoverageLevel::Definitive,
                evidence: Vec::new(),
                suppression,
                expires_at: None,
            });
        }

        let behavior = behaviors
            .iter()
            .find(|behavior| {
                behavior
                    .name
                    .as_deref()
                    .and_then(|name| intent_of(name, &self.behavior_intents))
                    .is_some_and(|intent| intent == BehaviorIntent::Malicious)
            })
            .or_else(|| behaviors.first());

        let (assertion, category) = match behavior
            .as_ref()
            .and_then(|behavior| behavior.name.as_deref())
        {
            Some(name) => {
                let intent =
                    intent_of(name, &self.behavior_intents).unwrap_or(BehaviorIntent::Anomalous);
                (assertion_of(intent), threat_category(name))
            }
            None => (Assertion::Attack, ThreatCategory::GenericAbuse),
        };

        let expires_at = last_seen
            .map(|seen| seen + Duration::days(VALIDITY_DAYS))
            .unwrap_or(now + Duration::days(VALIDITY_DAYS));

        let observation_window = behavior.as_ref().and_then(|behavior| {
            let since = behavior.since.as_deref().and_then(parse_timestamp);
            let until = behavior.until.as_deref().and_then(parse_timestamp);
            match (since, until) {
                (Some(start), Some(end)) => Some(ObservationWindow { start, end }),
                _ => None,
            }
        });

        let evidence = Evidence {
            provider: ProviderId::CROWDSEC,
            family: SourceFamily::CROWDSEC,
            assertion,
            category,
            upstream_category: behavior.as_ref().and_then(|behavior| behavior.name.clone()),
            strength,
            scope: MatchScope::Exact,
            observed_at: last_seen,
            published_at: None,
            retrieved_at: Some(now),
            expires_at: Some(expires_at),
            observation_window,
            count: behavior.as_ref().and_then(|behavior| behavior.count),
            upstream_values,
        };

        Ok(ProviderFinding {
            provider: ProviderId::CROWDSEC,
            coverage: CoverageLevel::Definitive,
            evidence: vec![evidence],
            suppression,
            expires_at: Some(expires_at),
        })
    }
}

/// Parses an upstream timestamp.
pub fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SmokeResponse {
    #[serde(default)]
    reputation: Option<String>,
    #[serde(default)]
    reputation_score: Option<i64>,
    #[serde(default)]
    background_noise: Option<String>,
    #[serde(default)]
    background_noise_score: Option<i64>,
    #[serde(default)]
    classifications: Option<Classifications>,
    #[serde(default)]
    behaviors: Option<Vec<Behavior>>,
    #[serde(default)]
    references: Option<Vec<String>>,
    #[serde(default)]
    history: Option<History>,
    #[serde(default)]
    scores: Option<BTreeMap<String, i64>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Classifications {
    #[serde(default)]
    false_positives: Option<Vec<String>>,
    #[serde(default)]
    classifications: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Behavior {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    count: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct History {
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use super::{CrowdSecProvider, default_intents, intent_of, threat_category};
    use crate::model::{BehaviorIntent, ThreatCategory};
    use crate::provider::lookup::{ProviderRuntime, monthly_guard};
    use crate::provider::{LookupProvider, ProviderCost};
    use crate::secret::ApiKey;

    #[test]
    fn the_provider_states_its_cost() {
        let runtime = Arc::new(ProviderRuntime::new(
            crate::http::build_client(Duration::from_secs(5)).expect("the client is built"),
            monthly_guard(10),
            Duration::from_secs(5),
            crate::clock::system_clock(),
        ));
        let provider = CrowdSecProvider::new(
            ApiKey::new("test-key"),
            "https://cti.api.crowdsec.net/v2",
            BTreeMap::new(),
            runtime,
        );

        assert_eq!(provider.cost(), ProviderCost::High);
    }

    #[test]
    fn an_exploit_behavior_is_malicious() {
        let intents = BTreeMap::new();
        assert_eq!(
            intent_of("http:exploit", &intents),
            Some(BehaviorIntent::Malicious)
        );
    }

    #[test]
    fn a_scan_behavior_is_reconnaissance() {
        let intents = BTreeMap::new();
        assert_eq!(
            intent_of("generic:scan", &intents),
            Some(BehaviorIntent::Reconnaissance)
        );
    }

    #[test]
    fn an_override_wins_over_the_compiled_in_table() {
        let mut intents = default_intents().clone();
        intents.insert("http:scan".to_string(), BehaviorIntent::Malicious);
        assert_eq!(
            intent_of("http:scan", &intents),
            Some(BehaviorIntent::Malicious)
        );
    }

    #[test]
    fn a_behavior_maps_to_a_threat_category() {
        assert_eq!(threat_category("http:exploit"), ThreatCategory::WebAttack);
        assert_eq!(threat_category("http:scan"), ThreatCategory::Scanner);
    }
}
