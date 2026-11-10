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
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::index::ADDRESS_KEY;
use crate::model::{
    Assertion, Evidence, EvidenceStrength, MatchScope, ObservationWindow, ProviderId, SourceFamily,
    ThreatCategory,
};
use crate::provider::lookup::ProviderRuntime;
use crate::provider::services::{SERVICES, assertion_of, category_of};
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
        let network = network.trunc();

        let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
        upstream_values.insert("range_start".to_string(), columns[0].trim().to_string());
        upstream_values.insert("range_end".to_string(), columns[1].trim().to_string());
        upstream_values.insert("targets".to_string(), count.to_string());
        insert_value(&mut upstream_values, "network", columns[4]);
        insert_value(&mut upstream_values, "country", columns[5]);
        insert_value(&mut upstream_values, "contact", columns[6]);

        entries.push(Evidence {
            provider: ProviderId::DSHIELD,
            family: SourceFamily::DSHIELD,
            assertion: Assertion::Reconnaissance,
            category: ThreatCategory::Scanner,
            upstream_category: None,
            strength: EvidenceStrength::Indicative,
            scope: MatchScope::Prefix { network },
            observed_at: None,
            published_at,
            retrieved_at: Some(now),
            expires_at: Some(end + BLOCK_WINDOW),
            observation_window: Some(ObservationWindow { start, end }),
            count: Some(count),
            upstream_values,
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
            let label = other.strip_prefix("blocklistde")?;
            let (assertion, category) = match service_of(label) {
                Some(service) => (assertion_of(service), category_of(service)),
                None => (Assertion::Abuse, ThreatCategory::GenericAbuse),
            };
            (
                SourceFamily::BLOCKLIST_DE,
                assertion,
                category,
                EvidenceStrength::Indicative,
            )
        }
    };

    let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
    upstream_values.insert(ADDRESS_KEY.to_string(), address.to_string());
    upstream_values.insert("label".to_string(), label.to_string());
    upstream_values.insert("firstseen".to_string(), columns[0].trim().to_string());
    insert_value(&mut upstream_values, "country", columns[4]);

    Some(Evidence {
        provider: ProviderId::DSHIELD,
        family,
        assertion,
        category,
        upstream_category: Some(label.to_string()),
        strength,
        scope: MatchScope::Exact,
        observed_at: Some(last_seen),
        published_at: None,
        retrieved_at: Some(now),
        expires_at: Some(last_seen + THREATINTEL_WINDOW),
        observation_window: None,
        count: None,
        upstream_values,
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
        let position = find_update(line)?;
        let mut rest = line[position + "update".len()..].trim();

        if rest.starts_with(['d', 'D']) {
            rest = rest[1..].trim();
        }
        let rest = rest.strip_prefix(':').unwrap_or(rest).trim();

        parse_timestamp(rest).or_else(|| rest.split_whitespace().next().and_then(parse_timestamp))
    })
}

/// The position of the word that names the publication time.
fn find_update(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(6))
        .find(|&index| line[index..index + 6].eq_ignore_ascii_case("update"))
}

/// Records a value the publisher left empty.
fn insert_value(upstream_values: &mut BTreeMap<String, String>, key: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() || value == "-" || value == "None" {
        return;
    }
    upstream_values.insert(key.to_string(), value.to_string());
}

/// The service a label of another publisher names.
///
/// The publisher names the services of the list by their name, and some of
/// them by the port they serve.
fn service_of(label: &str) -> Option<&'static str> {
    match label {
        "22" => Some("ssh"),
        "21" => Some("ftp"),
        "25" => Some("mail"),
        "110" | "143" | "993" | "courierimap" => Some("imap"),
        "80" | "443" => Some("apache"),
        other => SERVICES.iter().find(|service| **service == other).copied(),
    }
}

/// Parses the publication time of a list.
///
/// The publisher writes the time in ISO 8601, with or without an offset.
fn parse_timestamp(text: &str) -> Option<OffsetDateTime> {
    let text = text.trim();
    let (date, time) = text.split_once(['T', ' '])?;

    let date = time::Date::parse(
        date.trim(),
        &time::macros::format_description!("[year]-[month]-[day]"),
    )
    .ok()?;

    let (time, offset) = split_offset(time.trim());
    let (clock, fraction) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, fraction),
        None => (time, ""),
    };

    let clock = time::Time::parse(
        clock,
        &time::macros::format_description!("[hour]:[minute]:[second]"),
    )
    .ok()?;

    let nanoseconds = nanoseconds_of(fraction)?;
    let timestamp = date.with_time(clock).assume_utc().to_offset(offset)
        + time::Duration::nanoseconds(i64::from(nanoseconds));

    Some(timestamp)
}

/// Splits the offset of a timestamp from the time of day.
fn split_offset(text: &str) -> (&str, time::UtcOffset) {
    if let Some(time) = text.strip_suffix('Z') {
        return (time, time::UtcOffset::UTC);
    }

    let position = text.rfind(['+', '-']);
    let Some(position) = position else {
        return (text, time::UtcOffset::UTC);
    };

    let sign = if text.as_bytes()[position] == b'+' {
        1
    } else {
        -1
    };
    let offset = text[position + 1..]
        .split_once(':')
        .and_then(|(hours, minutes)| {
            let hours: i8 = hours.parse().ok()?;
            let minutes: i8 = minutes.parse().ok()?;
            time::UtcOffset::from_hms(sign * hours, sign * minutes, 0).ok()
        });

    match offset {
        Some(offset) => (&text[..position], offset),
        None => (text, time::UtcOffset::UTC),
    }
}

/// The nanoseconds a fractional second stands for.
fn nanoseconds_of(fraction: &str) -> Option<u32> {
    if fraction.is_empty() {
        return Some(0);
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    let mut digits = fraction.to_string();
    digits.truncate(9);
    while digits.len() < 9 {
        digits.push('0');
    }
    digits.parse().ok()
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
