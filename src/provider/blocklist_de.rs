//! The Blocklist.de provider.
//!
//! The upstream publishes two products of one lineage: a per-address query that
//! counts the attack events a partner's sensors observed, and a set of
//! per-service lists that name the addresses those sensors saw. The query
//! carries a count and may corroborate; a list membership carries no count and
//! is only a signal.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::index::ADDRESS_KEY;
use crate::model::{
    Assertion, CoverageLevel, Evidence, EvidenceStrength, MatchScope, ObservationWindow,
    ProviderId, SourceFamily, ThreatCategory,
};
use crate::provider::lookup::{ProviderRuntime, parse_body};
use crate::provider::{
    FeedProvider, FeedSnapshot, LookupProvider, ProviderCapability, ProviderVerdict,
};

/// The number of attack events an observation needs.
pub const MIN_ATTACK_EVENTS: u32 = 3;

/// The time a query answer stays usable.
pub const VALIDITY: time::Duration = time::Duration::hours(48);

/// The services the upstream publishes a list for.
pub const SERVICES: &[&str] = &[
    "all",
    "ssh",
    "apache",
    "imap",
    "ftp",
    "sip",
    "bots",
    "bruteforcelogin",
    "strongips",
];

/// The kind of activity a service list reports.
pub fn category_of(service: &str) -> ThreatCategory {
    match service {
        "ssh" | "imap" | "ftp" | "sip" | "bruteforcelogin" => ThreatCategory::BruteForce,
        "apache" => ThreatCategory::WebAttack,
        "mail" => ThreatCategory::SpamAbuse,
        _ => ThreatCategory::GenericAbuse,
    }
}

/// The claim a service list makes.
pub fn assertion_of(service: &str) -> Assertion {
    match service {
        "bots" | "mail" => Assertion::Abuse,
        _ => Assertion::Attack,
    }
}

/// The time a service list stays usable.
pub fn validity_of(service: &str) -> time::Duration {
    match service {
        "strongips" => time::Duration::days(7),
        _ => time::Duration::hours(48),
    }
}

/// The Blocklist.de per-address query provider.
pub struct BlocklistDeQueryProvider {
    base_url: String,
    window: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl BlocklistDeQueryProvider {
    /// Creates a provider.
    pub fn new(
        base_url: impl Into<String>,
        window: Duration,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            window,
            runtime,
        }
    }
}

#[async_trait]
impl LookupProvider for BlocklistDeQueryProvider {
    fn id(&self) -> ProviderId {
        ProviderId::BLOCKLIST_DE
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::BLOCKLIST_DE
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    async fn lookup(&self, ip: IpAddr) -> Result<ProviderVerdict, ProviderError> {
        let now = self.runtime.clock().now();
        let start = now - time::Duration::seconds(self.window.as_secs() as i64);
        let url = format!("{}/api.php", self.base_url.trim_end_matches('/'));

        let request = self
            .runtime
            .client()
            .get(url)
            .header("Accept", "application/json")
            .query(&[
                ("ip", ip.to_string()),
                ("start", start.unix_timestamp().to_string()),
                ("end", now.unix_timestamp().to_string()),
                ("format", "json".to_string()),
            ]);

        let response = self.runtime.send_anonymous(request, now).await?;
        let body = self.runtime.read_body(response).await?;
        let parsed: QueryResponse = parse_body(&body)?;

        let attacks = parsed.attacks.unwrap_or_default();
        let reports = parsed.reports.unwrap_or_default();

        let mut raw_values: BTreeMap<String, String> = BTreeMap::new();
        raw_values.insert("attacks".to_string(), attacks.to_string());
        raw_values.insert("reports".to_string(), reports.to_string());

        if attacks < MIN_ATTACK_EVENTS {
            return Ok(ProviderVerdict {
                provider: ProviderId::BLOCKLIST_DE,
                coverage: CoverageLevel::Definitive,
                evidence: Vec::new(),
                suppression: None,
                expires_at: None,
            });
        }

        let expires_at = now + VALIDITY;
        let evidence = Evidence {
            provider: ProviderId::BLOCKLIST_DE,
            family: SourceFamily::BLOCKLIST_DE,
            assertion: Assertion::Attack,
            category: ThreatCategory::GenericAbuse,
            raw_category: None,
            strength: EvidenceStrength::Corroborating,
            scope: MatchScope::Exact,
            observed_at: Some(now),
            published_at: None,
            retrieved_at: Some(now),
            expires_at: Some(expires_at),
            observation_window: Some(ObservationWindow { start, end: now }),
            count: Some(attacks),
            raw_values,
        };

        Ok(ProviderVerdict {
            provider: ProviderId::BLOCKLIST_DE,
            coverage: CoverageLevel::Definitive,
            evidence: vec![evidence],
            suppression: None,
            expires_at: Some(expires_at),
        })
    }
}

/// The answer of the per-address query.
#[derive(Clone, Debug, Deserialize)]
struct QueryResponse {
    #[serde(default)]
    attacks: Option<u32>,
    #[serde(default)]
    reports: Option<u32>,
}

/// The Blocklist.de service list provider.
pub struct BlocklistDeListProvider {
    base_url: String,
    services: Vec<String>,
    min_refresh_interval: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl BlocklistDeListProvider {
    /// Creates a provider for the published services.
    pub fn new(
        base_url: impl Into<String>,
        min_refresh_interval: Duration,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            services: SERVICES.iter().map(|service| service.to_string()).collect(),
            min_refresh_interval,
            runtime,
        }
    }

    /// Creates a provider for a chosen set of services.
    pub fn with_services(
        base_url: impl Into<String>,
        services: Vec<String>,
        min_refresh_interval: Duration,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            services,
            min_refresh_interval,
            runtime,
        }
    }

    /// The URL of one of the service lists.
    fn url(&self, service: &str) -> String {
        format!(
            "{}/lists/{service}.txt",
            self.base_url.trim_end_matches('/')
        )
    }
}

#[async_trait]
impl FeedProvider for BlocklistDeListProvider {
    fn id(&self) -> ProviderId {
        ProviderId::BLOCKLIST_DE_LISTS
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::BLOCKLIST_DE
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        let now = self.runtime.clock().now();
        let mut entries = Vec::new();

        for service in &self.services {
            let request = self
                .runtime
                .client()
                .get(self.url(service))
                .header("Accept-Encoding", "gzip");
            let response = self.runtime.send_anonymous(request, now).await?;
            let body = self.runtime.read_body(response).await?;

            for address in parse_service_list(&body)? {
                entries.push(observation_for(service, address, now));
            }
        }

        Ok(FeedSnapshot {
            provider: ProviderId::BLOCKLIST_DE_LISTS,
            family: SourceFamily::BLOCKLIST_DE,
            published_at: None,
            retrieved_at: now,
            expires_at: Some(now + time::Duration::hours(48)),
            attribution: String::new(),
            header_lines: Vec::new(),
            entries,
        })
    }
}

/// Parses one service list.
///
/// The list holds one address per line. A line that is neither empty nor a
/// comment has to be an address, because a half-read list must not be served.
pub fn parse_service_list(body: &str) -> Result<Vec<IpAddr>, ProviderError> {
    if body.trim().is_empty() {
        return Err(ProviderError::Parse("the list is empty".to_string()));
    }

    let mut addresses = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let address = line
            .parse::<IpAddr>()
            .map_err(|error| ProviderError::Parse(error.to_string()))?;
        addresses.push(address);
    }

    Ok(addresses)
}

/// The observation of one address of a service list.
fn observation_for(service: &str, address: IpAddr, now: OffsetDateTime) -> Evidence {
    let mut raw_values: BTreeMap<String, String> = BTreeMap::new();
    raw_values.insert(ADDRESS_KEY.to_string(), address.to_string());
    raw_values.insert("service".to_string(), service.to_string());
    raw_values.insert("entry_observed_at".to_string(), "none".to_string());

    Evidence {
        provider: ProviderId::BLOCKLIST_DE_LISTS,
        family: SourceFamily::BLOCKLIST_DE,
        assertion: assertion_of(service),
        category: category_of(service),
        raw_category: None,
        strength: EvidenceStrength::Indicative,
        scope: MatchScope::Exact,
        observed_at: Some(now),
        published_at: None,
        retrieved_at: Some(now),
        expires_at: Some(now + validity_of(service)),
        observation_window: None,
        count: None,
        raw_values,
    }
}
