//! The Spamhaus DROP provider.
//!
//! The upstream publishes the networks that professional spam and cyber-crime
//! operations lease or steal. The listing is a statement about a range and
//! never about a single address, so an observation from this provider may only
//! corroborate the observation of another family.
//!
//! The provider is compiled in by the `spamhaus` crate feature. It expects no
//! credential: the lists it reads are published for everyone.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::model::{
    Assertion, Evidence, EvidenceStrength, MatchScope, ProviderId, SourceFamily, ThreatCategory,
};
use crate::provider::lookup::ProviderRuntime;
use crate::provider::{FeedProvider, FeedSnapshot, ProviderCapability};

/// The file name of the IPv4 list.
pub const DROP_V4_FILE: &str = "drop_v4.json";
/// The file name of the IPv6 list.
pub const DROP_V6_FILE: &str = "drop_v6.json";

/// The time a published listing stays usable.
pub const VALIDITY: time::Duration = time::Duration::hours(26);

/// The Spamhaus DROP provider.
pub struct SpamhausProvider {
    base_url: String,
    min_refresh_interval: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl SpamhausProvider {
    /// Creates a provider.
    pub fn new(
        base_url: impl Into<String>,
        min_refresh_interval: Duration,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            min_refresh_interval,
            runtime,
        }
    }

    /// The URL of one of the two lists.
    fn url(&self, file: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), file)
    }
}

#[async_trait]
impl FeedProvider for SpamhausProvider {
    fn id(&self) -> ProviderId {
        ProviderId::SPAMHAUS
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::SPAMHAUS
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
        let mut published_at: Option<OffsetDateTime> = None;
        let mut attribution: Option<String> = None;

        for file in [DROP_V4_FILE, DROP_V6_FILE] {
            let request = self
                .runtime
                .client()
                .get(self.url(file))
                .header("Accept", "application/json");
            let response = self.runtime.send_anonymous(request, now).await?;
            let body = self.runtime.read_body(response).await?;
            let list = parse_drop_list(&body, now)?;

            published_at = match (published_at, list.published_at) {
                (Some(current), Some(candidate)) => Some(current.min(candidate)),
                (current, None) => current,
                (None, candidate) => candidate,
            };
            if attribution.is_none() {
                attribution = list.attribution;
            }
            entries.extend(list.entries);
        }

        Ok(FeedSnapshot {
            provider: ProviderId::SPAMHAUS,
            family: SourceFamily::SPAMHAUS,
            published_at,
            retrieved_at: now,
            expires_at: published_at.map(|published| published + VALIDITY),
            attribution: attribution.unwrap_or_default(),
            header_lines: Vec::new(),
            entries,
        })
    }
}

/// One parsed DROP list.
pub struct DropList {
    /// The publication time the metadata carries.
    pub published_at: Option<OffsetDateTime>,
    /// The attribution the metadata carries.
    pub attribution: Option<String>,
    /// The observations of the list.
    pub entries: Vec<Evidence>,
}

/// Parses one DROP list.
///
/// The body is JSON Lines: one object per line, the last of which is the
/// metadata object. A line that is not valid JSON is a parse error, because a
/// half-read list must not be served.
pub fn parse_drop_list(body: &str, now: OffsetDateTime) -> Result<DropList, ProviderError> {
    let lines: Vec<&str> = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    if lines.is_empty() {
        return Err(ProviderError::Parse("the list is empty".to_string()));
    }

    let mut metadata: Option<DropMetadata> = None;
    let mut raw_entries: Vec<Value> = Vec::new();

    for line in &lines {
        let value: Value =
            serde_json::from_str(line).map_err(|error| ProviderError::Parse(error.to_string()))?;

        if value.get("type").and_then(Value::as_str) == Some("metadata") {
            metadata = Some(
                serde_json::from_value(value)
                    .map_err(|error| ProviderError::Parse(error.to_string()))?,
            );
            continue;
        }

        raw_entries.push(value);
    }

    let published_at = metadata.as_ref().and_then(DropMetadata::published_at);
    let attribution = metadata
        .as_ref()
        .and_then(DropMetadata::attribution)
        .filter(|attribution| !attribution.is_empty());
    let expires_at = published_at.map(|published| published + VALIDITY);

    let mut entries = Vec::with_capacity(raw_entries.len());
    for value in raw_entries {
        let entry: DropEntry = serde_json::from_value(value)
            .map_err(|error| ProviderError::Parse(error.to_string()))?;
        let network: IpNet = entry
            .cidr
            .parse::<IpNet>()
            .map_err(|error| ProviderError::Parse(error.to_string()))?;

        let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
        if let Some(sblid) = entry.sblid {
            upstream_values.insert("sblid".to_string(), sblid);
        }
        if let Some(rir) = entry.rir {
            upstream_values.insert("rir".to_string(), rir);
        }

        entries.push(Evidence {
            provider: ProviderId::SPAMHAUS,
            family: SourceFamily::SPAMHAUS,
            assertion: Assertion::NetworkControl,
            category: ThreatCategory::MaliciousNetwork,
            upstream_category: None,
            strength: EvidenceStrength::Corroborating,
            scope: MatchScope::Prefix { network },
            observed_at: None,
            published_at,
            retrieved_at: Some(now),
            expires_at,
            observation_window: None,
            count: None,
            upstream_values,
        });
    }

    Ok(DropList {
        published_at,
        attribution,
        entries,
    })
}

/// The metadata object of a DROP list.
#[derive(Clone, Debug, Deserialize)]
struct DropMetadata {
    #[serde(default)]
    timestamp: Option<Value>,
    #[serde(default)]
    copyright: Option<String>,
    #[serde(default)]
    terms: Option<String>,
}

impl DropMetadata {
    /// The publication time of the list.
    fn published_at(&self) -> Option<OffsetDateTime> {
        parse_timestamp(self.timestamp.as_ref()?)
    }

    /// The attribution the upstream asks for.
    fn attribution(&self) -> Option<String> {
        let copyright = self.copyright.as_deref().unwrap_or_default().trim();
        let terms = self.terms.as_deref().unwrap_or_default().trim();

        match (copyright.is_empty(), terms.is_empty()) {
            (true, true) => None,
            (true, false) => Some(terms.to_string()),
            (false, true) => Some(copyright.to_string()),
            (false, false) => Some(format!("{copyright}\n{terms}")),
        }
    }
}

/// One entry of a DROP list.
#[derive(Clone, Debug, Deserialize)]
struct DropEntry {
    cidr: String,
    #[serde(default)]
    sblid: Option<String>,
    #[serde(default)]
    rir: Option<String>,
}

/// Parses the publication time of a list.
///
/// The upstream states the time either as a number of seconds since the epoch
/// or as a timestamp in the RFC 3339 format.
fn parse_timestamp(value: &Value) -> Option<OffsetDateTime> {
    if let Some(seconds) = value.as_i64() {
        return OffsetDateTime::from_unix_timestamp(seconds).ok();
    }

    let text = value.as_str()?;
    if let Ok(timestamp) =
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
    {
        return Some(timestamp);
    }
    text.parse::<i64>()
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
}
