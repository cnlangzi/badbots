//! The AbuseIPDB check provider.
//!
//! The upstream publishes the confidence score of an address, the number of
//! distinct reporters and the categories those reporters chose. The key is sent
//! in the `Key` header because upstream logs query strings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use time::{Duration, OffsetDateTime};

use crate::engine::rules;
use crate::error::ProviderError;
use crate::model::{
    Assertion, CoverageLevel, Evidence, MatchScope, ProviderId, SourceFamily, Suppression,
    ThreatCategory,
};
use crate::provider::lookup::{ProviderRuntime, parse_body};
use crate::provider::{LookupProvider, ProviderCapability, ProviderVerdict};
use crate::secret::ApiKey;

/// The number of days a positive result stays usable.
pub const VALIDITY_DAYS: i64 = 30;

/// The upstream category identifiers that belong to the inbound attack set.
pub const INBOUND_ATTACK_CATEGORIES: &[u32] = &[1, 2, 4, 5, 7, 15, 16, 18, 20, 21, 22, 23];

/// The upstream category identifiers that report scanning.
pub const RECONNAISSANCE_CATEGORIES: &[u32] = &[14];

/// The upstream category identifiers that report spam abuse.
pub const ABUSE_CATEGORIES: &[u32] = &[10, 11, 12];

/// The claim and the threat category an upstream category identifier carries.
pub fn category_of(id: u32) -> Option<(Assertion, ThreatCategory)> {
    let inbound = INBOUND_ATTACK_CATEGORIES.contains(&id);
    let reconnaissance = RECONNAISSANCE_CATEGORIES.contains(&id);
    let abuse = ABUSE_CATEGORIES.contains(&id);

    if !inbound && !reconnaissance && !abuse {
        return None;
    }

    let category = match id {
        4 => ThreatCategory::Ddos,
        5 | 18 | 22 => ThreatCategory::BruteForce,
        7 | 16 | 21 => ThreatCategory::WebAttack,
        14 => ThreatCategory::Scanner,
        10..=12 => ThreatCategory::SpamAbuse,
        15 | 20 | 23 => ThreatCategory::BotnetOrMalware,
        _ => ThreatCategory::GenericAbuse,
    };

    let assertion = if inbound {
        Assertion::Attack
    } else if reconnaissance {
        Assertion::Reconnaissance
    } else {
        Assertion::Abuse
    };

    Some((assertion, category))
}

/// The AbuseIPDB check provider.
pub struct AbuseIpdbProvider {
    api_key: ApiKey,
    base_url: String,
    max_age_days: u32,
    runtime: Arc<ProviderRuntime>,
}

impl AbuseIpdbProvider {
    /// Creates a provider.
    pub fn new(
        api_key: ApiKey,
        base_url: impl Into<String>,
        max_age_days: u32,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            api_key,
            base_url: base_url.into(),
            max_age_days,
            runtime,
        }
    }
}

#[async_trait]
impl LookupProvider for AbuseIpdbProvider {
    fn id(&self) -> ProviderId {
        ProviderId::ABUSEIPDB
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::ABUSEIPDB
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Primary
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderVerdict, ProviderError> {
        let now = self.runtime.clock().now();
        let url = format!("{}/check", self.base_url.trim_end_matches('/'));
        let request = self
            .runtime
            .client()
            .get(url)
            .header("Key", self.api_key.expose())
            .header("Accept", "application/json")
            .query(&[
                ("ipAddress", ip.to_string()),
                ("maxAgeInDays", self.max_age_days.to_string()),
                ("verbose", "true".to_string()),
            ]);

        let response = self.runtime.send(request, now).await?;
        let body = self.runtime.read_body(response).await?;
        let parsed: CheckResponse = parse_body(&body)?;
        let data = parsed.data;

        if data.is_whitelisted == Some(true) {
            return Ok(ProviderVerdict {
                provider: ProviderId::ABUSEIPDB,
                coverage: CoverageLevel::Definitive,
                evidence: Vec::new(),
                suppression: Some(Suppression::Safe),
                expires_at: None,
            });
        }

        let score = data.abuse_confidence_score.unwrap_or_default().max(0) as u32;
        let distinct_users = data.num_distinct_users.unwrap_or_default();
        let total_reports = data.total_reports.unwrap_or_default();

        let category_ids: BTreeSet<u32> = data
            .reports
            .iter()
            .flatten()
            .flat_map(|report| report.categories.iter().flatten().copied())
            .collect();

        let inbound: Vec<(u32, Assertion, ThreatCategory)> = category_ids
            .iter()
            .filter_map(|id| {
                category_of(*id).map(|(assertion, category)| (*id, assertion, category))
            })
            .filter(|(_, assertion, _)| assertion.is_inbound_attack())
            .collect();

        let last_reported_at = data.last_reported_at.as_deref().and_then(parse_timestamp);
        let report_within_window = match last_reported_at {
            Some(reported) => {
                let age = now - reported;
                age.is_negative()
                    || age.unsigned_abs()
                        <= std::time::Duration::from_secs(
                            rules::abuseipdb::MAX_REPORT_AGE_DAYS as u64 * 86_400,
                        )
            }
            None => false,
        };

        let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
        upstream_values.insert("abuse_confidence_score".to_string(), score.to_string());
        upstream_values.insert("num_distinct_users".to_string(), distinct_users.to_string());
        upstream_values.insert("total_reports".to_string(), total_reports.to_string());
        upstream_values.insert(
            "categories".to_string(),
            category_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        if let Some(usage_type) = &data.usage_type {
            upstream_values.insert("usage_type".to_string(), usage_type.clone());
        }
        if let Some(country_code) = &data.country_code {
            upstream_values.insert("country_code".to_string(), country_code.clone());
        }
        if let Some(isp) = &data.isp {
            upstream_values.insert("isp".to_string(), isp.clone());
        }
        if let Some(domain) = &data.domain {
            upstream_values.insert("domain".to_string(), domain.clone());
        }
        if let Some(is_tor) = data.is_tor {
            upstream_values.insert("is_tor".to_string(), is_tor.to_string());
        }

        let strength = rules::abuseipdb::strength(
            score,
            distinct_users,
            !inbound.is_empty(),
            report_within_window,
        );

        let Some(strength) = strength else {
            return Ok(ProviderVerdict::empty(
                ProviderId::ABUSEIPDB,
                CoverageLevel::Definitive,
            ));
        };

        let (_, assertion, category) = inbound[0];
        let expires_at = last_reported_at
            .map(|reported| reported + Duration::days(VALIDITY_DAYS))
            .unwrap_or(now + Duration::days(VALIDITY_DAYS));

        let evidence = Evidence {
            provider: ProviderId::ABUSEIPDB,
            family: SourceFamily::ABUSEIPDB,
            assertion,
            category,
            upstream_category: inbound.first().map(|(id, _, _)| id.to_string()),
            strength,
            scope: MatchScope::Exact,
            observed_at: last_reported_at,
            published_at: None,
            retrieved_at: Some(now),
            expires_at: Some(expires_at),
            observation_window: None,
            count: Some(total_reports),
            upstream_values,
        };

        Ok(ProviderVerdict {
            provider: ProviderId::ABUSEIPDB,
            coverage: CoverageLevel::Definitive,
            evidence: vec![evidence],
            suppression: None,
            expires_at: Some(expires_at),
        })
    }
}

/// Parses an upstream timestamp.
pub fn parse_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckResponse {
    data: CheckData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckData {
    #[serde(default)]
    abuse_confidence_score: Option<i64>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    is_tor: Option<bool>,
    #[serde(default)]
    is_whitelisted: Option<bool>,
    #[serde(default)]
    total_reports: Option<u32>,
    #[serde(default)]
    num_distinct_users: Option<u32>,
    #[serde(default)]
    last_reported_at: Option<String>,
    #[serde(default)]
    reports: Option<Vec<Report>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    #[serde(default)]
    categories: Option<Vec<u32>>,
}

#[cfg(test)]
mod tests {
    use super::{INBOUND_ATTACK_CATEGORIES, category_of};
    use crate::model::{Assertion, ThreatCategory};

    #[test]
    fn the_inbound_attack_categories_are_mapped() {
        for id in INBOUND_ATTACK_CATEGORIES {
            let (assertion, _) = category_of(*id).expect("category is mapped");
            assert_eq!(assertion, Assertion::Attack);
        }
    }

    #[test]
    fn a_port_scan_is_reconnaissance() {
        let (assertion, category) = category_of(14).unwrap();
        assert_eq!(assertion, Assertion::Reconnaissance);
        assert_eq!(category, ThreatCategory::Scanner);
    }

    #[test]
    fn categories_outside_the_taxonomy_are_not_emitted() {
        assert!(category_of(19).is_none());
        assert!(category_of(13).is_none());
    }
}
