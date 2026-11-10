//! The DShield provider.
//!
//! The upstream publishes the subnets its sensors saw scanning and the
//! addresses its sensors saw attacking. A block record describes a range, so it
//! is only a signal; a threat intelligence record describes a single address.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ipnet::IpNet;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::error::ProviderError;
use crate::index::ADDRESS_KEY;
use crate::model::{
    Assertion, Evidence, EvidenceStrength, MatchScope, ObservationWindow, ProviderId, SourceFamily,
    ThreatCategory,
};
use crate::provider::blocklist_de;
use crate::provider::lookup::ProviderRuntime;
use crate::provider::{FeedProvider, FeedSnapshot, ProviderCapability};

/// The file name of the subnet list.
pub const BLOCK_FILE: &str = "block.txt";
/// The file name of the per-address list.
pub const THREATINTEL_FILE: &str = "threatintel.txt";

/// The time the subnet list covers.
pub const BLOCK_WINDOW: time::Duration = time::Duration::days(3);

/// The time an address stays in the per-address list.
pub const THREATINTEL_WINDOW: time::Duration = time::Duration::days(7);

/// The user agent the provider sends when the configuration does not set one.
pub const DEFAULT_USER_AGENT: &str = concat!(
    "badbots/",
    env!("CARGO_PKG_VERSION"),
    " (feed reader; contact: https://github.com/cnlangzi/badbots/issues)"
);

/// The DShield list provider.
pub struct DShieldProvider {
    base_url: String,
    user_agent: String,
    min_refresh_interval: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl DShieldProvider {
    /// Creates a provider.
    pub fn new(
        base_url: impl Into<String>,
        user_agent: impl Into<String>,
        min_refresh_interval: Duration,
        runtime: Arc<ProviderRuntime>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            user_agent: user_agent.into(),
            min_refresh_interval,
            runtime,
        }
    }

    /// The URL of one of the lists.
    fn url(&self, file: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), file)
    }
}

#[async_trait]
impl FeedProvider for DShieldProvider {
    fn id(&self) -> ProviderId {
        ProviderId::DSHIELD
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::DSHIELD
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        let now = self.runtime.clock().now();
        let block = self.fetch_file(BLOCK_FILE, now).await?;
        let threatintel = self.fetch_file(THREATINTEL_FILE, now).await?;

        let published_at = match (block.published_at, threatintel.published_at) {
            (Some(current), Some(candidate)) => Some(current.min(candidate)),
            (current, None) => current,
            (None, candidate) => candidate,
        };

        let mut header_lines = block.header_lines;
        header_lines.extend(threatintel.header_lines);

        let mut entries = block.entries;
        entries.extend(threatintel.entries);

        Ok(FeedSnapshot {
            provider: ProviderId::DSHIELD,
            family: SourceFamily::DSHIELD,
            published_at,
            retrieved_at: now,
            expires_at: published_at.map(|published| published + THREATINTEL_WINDOW),
            attribution: String::new(),
            header_lines,
            entries,
        })
    }
}

impl DShieldProvider {
    async fn fetch_file(
        &self,
        file: &str,
        now: OffsetDateTime,
    ) -> Result<ParsedList, ProviderError> {
        let request = self
            .runtime
            .client()
            .get(self.url(file))
            .header("User-Agent", &self.user_agent);
        let response = self.runtime.send_anonymous(request, now).await?;
        let body = self.runtime.read_body(response).await?;

        match file {
            BLOCK_FILE => parse_block_list(&body, now),
            _ => parse_threatintel(&body, now),
        }
    }
}

/// One parsed list of the publisher.
pub struct ParsedList {
    /// The publication time the header carries.
    pub published_at: Option<OffsetDateTime>,
    /// The header lines of the list.
    pub header_lines: Vec<String>,
    /// The observations of the list.
    pub entries: Vec<Evidence>,
}

/// Parses the subnet list.
///
/// A record holds the start address, the end address, the prefix length, the
/// number of targets that saw activity, the network name, the country and the
/// contact address. A record that does not hold all of them is skipped, because
/// the rest of the file still describes usable observations.
pub fn parse_block_list(body: &str, now: OffsetDateTime) -> Result<ParsedList, ProviderError> {
    let (header_lines, records) = split(body)?;

    if records.is_empty() {
        return Err(ProviderError::Parse("the list holds no record".to_string()));
    }

    let published_at = published_at_of(&header_lines);
    let end = published_at.unwrap_or(now);
    let start = end - BLOCK_WINDOW;

    let mut entries = Vec::new();
    for record in records {
        let columns: Vec<&str> = record.split('\t').collect();
        if columns.len() < 7 {
            continue;
        }

        let Ok(address) = columns[0].trim().parse::<IpAddr>() else {
            continue;
        };
        let Ok(prefix_len) = columns[2].trim().parse::<u8>() else {
            continue;
        };
        let Ok(count) = columns[3].trim().parse::<u32>() else {
            continue;
        };
        let Ok(network) = IpNet::new(address, prefix_len) else {
            continue;
        };

        let mut raw_values: BTreeMap<String, String> = BTreeMap::new();
        raw_values.insert("range_start".to_string(), columns[0].trim().to_string());
        raw_values.insert("range_end".to_string(), columns[1].trim().to_string());
        raw_values.insert("targets".to_string(), count.to_string());
        insert_value(&mut raw_values, "network", columns[4]);
        insert_value(&mut raw_values, "country", columns[5]);
        insert_value(&mut raw_values, "contact", columns[6]);

        entries.push(Evidence {
            provider: ProviderId::DSHIELD,
            family: SourceFamily::DSHIELD,
            assertion: Assertion::Reconnaissance,
            category: ThreatCategory::Scanner,
            raw_category: None,
            strength: EvidenceStrength::Indicative,
            scope: MatchScope::Prefix { network },
            observed_at: None,
            published_at,
            retrieved_at: Some(now),
            expires_at: Some(end + BLOCK_WINDOW),
            observation_window: Some(ObservationWindow { start, end }),
            count: Some(count),
            raw_values,
        });
    }

    Ok(ParsedList {
        published_at,
        header_lines,
        entries,
    })
}

/// Parses the per-address list.
///
/// A record holds the date the address was first seen, the date it was last
/// seen, the address, the label and the country. An address that was last seen
/// outside the window of the list is not an observation any more.
pub fn parse_threatintel(body: &str, now: OffsetDateTime) -> Result<ParsedList, ProviderError> {
    let (header_lines, records) = split(body)?;

    if records.is_empty() {
        return Err(ProviderError::Parse("the list holds no record".to_string()));
    }

    let published_at = published_at_of(&header_lines);
    let mut entries = Vec::new();

    for record in records {
        let columns: Vec<&str> = record.split('\t').collect();
        if columns.len() < 5 {
            continue;
        }

        let Some(last_seen) = parse_date(columns[1].trim()) else {
            continue;
        };
        if now - last_seen > THREATINTEL_WINDOW {
            continue;
        }
        let Ok(address) = columns[2].trim().parse::<IpAddr>() else {
            continue;
        };
        let label = columns[3].trim();

        let Some(evidence) = observation_for(label, address, &columns, last_seen, now) else {
            continue;
        };
        entries.push(evidence);
    }

    Ok(ParsedList {
        published_at,
        header_lines,
        entries,
    })
}

/// The observation of one labelled address.
///
/// The labels the publisher uses describe many kinds of context, so only the
/// labels that name an attack or an abuse are read. A label that names another
/// publisher's data keeps that publisher's lineage, so that the data and its
/// origin do not count as two votes.
fn observation_for(
    label: &str,
    address: IpAddr,
    columns: &[&str],
    last_seen: OffsetDateTime,
    now: OffsetDateTime,
) -> Option<Evidence> {
    let (family, assertion, category, strength) = match label {
        "dshieldssh" => (
            SourceFamily::DSHIELD,
            Assertion::Attack,
            ThreatCategory::BruteForce,
            EvidenceStrength::Corroborating,
        ),
        "webscanner" => (
            SourceFamily::DSHIELD,
            Assertion::Attack,
            ThreatCategory::Scanner,
            EvidenceStrength::Corroborating,
        ),
        "forumspam" => (
            SourceFamily::DSHIELD,
            Assertion::Abuse,
            ThreatCategory::SpamAbuse,
            EvidenceStrength::Indicative,
        ),
        other => {
            let service = other.strip_prefix("blocklistde")?;
            (
                SourceFamily::BLOCKLIST_DE,
                blocklist_de::assertion_of(service),
                blocklist_de::category_of(service),
                EvidenceStrength::Indicative,
            )
        }
    };

    let mut raw_values: BTreeMap<String, String> = BTreeMap::new();
    raw_values.insert(ADDRESS_KEY.to_string(), address.to_string());
    raw_values.insert("label".to_string(), label.to_string());
    raw_values.insert("firstseen".to_string(), columns[0].trim().to_string());
    insert_value(&mut raw_values, "country", columns[4]);

    Some(Evidence {
        provider: ProviderId::DSHIELD,
        family,
        assertion,
        category,
        raw_category: Some(label.to_string()),
        strength,
        scope: MatchScope::Exact,
        observed_at: Some(last_seen),
        published_at: None,
        retrieved_at: Some(now),
        expires_at: Some(last_seen + THREATINTEL_WINDOW),
        observation_window: None,
        count: None,
        raw_values,
    })
}

/// Splits a list into its header lines and its records.
fn split(body: &str) -> Result<(Vec<String>, Vec<&str>), ProviderError> {
    if body.trim().is_empty() {
        return Err(ProviderError::Parse("the list is empty".to_string()));
    }

    let mut header_lines = Vec::new();
    let mut records = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            header_lines.push(line.trim_start_matches('#').trim().to_string());
            continue;
        }
        records.push(line);
    }

    Ok((header_lines, records))
}

/// The publication time the header of a list carries.
fn published_at_of(header_lines: &[String]) -> Option<OffsetDateTime> {
    header_lines.iter().rev().find_map(|line| {
        let position = find_updated(line)?;
        let rest = line[position + "updated".len()..].trim();
        parse_timestamp(rest).or_else(|| {
            rest.split_once(':')
                .and_then(|(_, value)| parse_timestamp(value.trim()))
        })
    })
}

/// The position of the word that names the publication time.
fn find_updated(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(7))
        .find(|&index| line[index..index + 7].eq_ignore_ascii_case("updated"))
}

/// Records a value the publisher left empty.
fn insert_value(raw_values: &mut BTreeMap<String, String>, key: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return;
    }
    raw_values.insert(key.to_string(), value.to_string());
}

/// Parses the publication time of a list.
///
/// The publisher writes the time in UTC without an offset, so the formats
/// without one are read as UTC.
fn parse_timestamp(text: &str) -> Option<OffsetDateTime> {
    let text = text.trim();

    if let Ok(timestamp) =
        OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
    {
        return Some(timestamp);
    }
    if let Ok(timestamp) = PrimitiveDateTime::parse(
        text,
        &time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC"),
    ) {
        return Some(timestamp.assume_utc());
    }
    PrimitiveDateTime::parse(
        text,
        &time::macros::format_description!(
            "[weekday repr:short] [month repr:short] [day] [hour]:[minute]:[second] [year] UTC"
        ),
    )
    .ok()
    .map(|timestamp| timestamp.assume_utc())
}

/// Parses a date of a list.
fn parse_date(text: &str) -> Option<OffsetDateTime> {
    time::Date::parse(
        text.trim(),
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()
    .map(|date| date.midnight().assume_utc())
}
