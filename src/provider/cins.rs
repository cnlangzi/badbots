//! The CINS Army list provider.
//!
//! The upstream publishes the addresses its Sentinel sensors saw attacking. The
//! observations come from the sensors of the publisher and not from a
//! redistribution of somebody else's feed, so they corroborate the
//! observations of the other providers.
//!
//! The provider is compiled in by the `cins` crate feature. It expects no
//! credential: the list it reads is published for everyone. The publisher
//! states no cadence for the list, so the provider waits a day between two
//! attempts, because the file that was observed carried the day of the
//! observation in its `Last-Modified` header.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::index::ip_index::ADDRESS_KEY;
use crate::model::{
    Assertion, Evidence, EvidenceStrength, MatchScope, ProviderId, SourceFamily, ThreatCategory,
};
use crate::provider::lookup::ProviderRuntime;
use crate::provider::{FeedProvider, FeedSnapshot, ProviderCapability};

/// The path of the list of the addresses that were seen attacking.
pub const LIST_PATH: &str = "list/ci-badguys.txt";

/// The time an observation of the list stays usable.
pub const VALIDITY: time::Duration = time::Duration::hours(24);

/// The attribution the snapshot carries.
pub const ATTRIBUTION: &str = concat!(
    "CINS Army list of high-risk IP addresses, produced by CINS Active Threat ",
    "Intelligence (Sentinel IPS). Published daily, capped at 15,000 addresses. ",
    "https://cinsscore.com/list/"
);

/// The CINS Army list provider.
pub struct CinsProvider {
    base_url: String,
    min_refresh_interval: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl CinsProvider {
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

    /// The URL of the list.
    fn url(&self) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), LIST_PATH)
    }
}

#[async_trait]
impl FeedProvider for CinsProvider {
    fn id(&self) -> ProviderId {
        ProviderId::CINS
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::CINS
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        let now = self.runtime.clock().now();
        let request = self.runtime.client().get(self.url());
        let response = self.runtime.send_anonymous(request, now).await?;
        let body = self.runtime.read_body(response).await?;
        let list = parse_list(&body, now)?;

        Ok(FeedSnapshot {
            provider: ProviderId::CINS,
            family: SourceFamily::CINS,
            published_at: None,
            retrieved_at: now,
            expires_at: Some(list.expires_at),
            attribution: ATTRIBUTION.to_string(),
            header_lines: list.header_lines,
            entries: list.entries,
        })
    }
}

/// One parsed list of the publisher.
pub struct ParsedList {
    /// The header lines of the list.
    pub header_lines: Vec<String>,
    /// The observations of the list.
    pub entries: Vec<Evidence>,
    /// The instant the observations of the list stop being usable.
    pub expires_at: OffsetDateTime,
}

/// Parses the list of the addresses that were seen attacking.
///
/// The lines that begin with `#` are the header of the list and are kept
/// verbatim. Every other line is split on whitespace and every token is
/// parsed on its own: a token that carries a prefix is dropped, and so is a
/// token that does not parse. A body that names no address at all is a parse
/// error, so that a list whose format changed empties no index and keeps the
/// snapshot that was loaded before.
pub fn parse_list(body: &str, now: OffsetDateTime) -> Result<ParsedList, ProviderError> {
    if body.trim().is_empty() {
        return Err(ProviderError::Parse("the list is empty".to_string()));
    }

    let mut header_lines = Vec::new();
    let mut addresses = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            header_lines.push(line.trim_start_matches('#').trim().to_string());
            continue;
        }
        addresses.extend(addresses_of(line));
    }

    if addresses.is_empty() {
        return Err(ProviderError::Parse(
            "the list holds no address".to_string(),
        ));
    }

    let expires_at = now + VALIDITY;
    let entries = addresses
        .into_iter()
        .map(|address| observation_for(address, now, expires_at))
        .collect();

    Ok(ParsedList {
        header_lines,
        entries,
        expires_at,
    })
}

/// The addresses one data line names.
///
/// The publisher's file loses a line break now and then, so a line may hold two
/// addresses glued together. A token that carries a prefix is dropped, because
/// the observation of a range belongs to a source of ranges, and a token that
/// does not parse is dropped, which covers a glued pair as well: no address may
/// ever be guessed.
fn addresses_of(line: &str) -> impl Iterator<Item = IpAddr> {
    line.split_whitespace().filter_map(|token| {
        if token.contains('/') {
            return None;
        }
        token.parse::<IpAddr>().ok()
    })
}

/// The observation of one address of the list.
///
/// The publisher does not say when it saw the address and states no
/// publication time for the list either, so the observation carries no
/// observation time and no publication time.
fn observation_for(address: IpAddr, now: OffsetDateTime, expires_at: OffsetDateTime) -> Evidence {
    let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
    upstream_values.insert(ADDRESS_KEY.to_string(), address.to_string());

    Evidence {
        provider: ProviderId::CINS,
        family: SourceFamily::CINS,
        assertion: Assertion::Attack,
        category: ThreatCategory::GenericAbuse,
        upstream_category: None,
        strength: EvidenceStrength::Convicting,
        scope: MatchScope::Exact,
        observed_at: None,
        published_at: None,
        retrieved_at: Some(now),
        expires_at: Some(expires_at),
        observation_window: None,
        count: None,
        upstream_values,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use time::macros::datetime;

    use super::{CinsProvider, LIST_PATH, addresses_of, parse_list};
    use crate::config::{CINS_DEFAULT_BASE_URL, CINS_DEFAULT_MIN_REFRESH_INTERVAL};
    use crate::provider::lookup::ProviderRuntime;
    use crate::quota::daily_guard;

    fn now() -> time::OffsetDateTime {
        datetime!(2026-11-13 12:00:00 UTC)
    }

    fn runtime() -> Arc<ProviderRuntime> {
        Arc::new(ProviderRuntime::new(
            crate::http::build_client(Duration::from_secs(5)).expect("the client is built"),
            daily_guard(10),
            Duration::from_secs(5),
            crate::clock::system_clock(),
        ))
    }

    #[test]
    fn the_default_base_url_names_the_list() {
        let provider = CinsProvider::new(
            CINS_DEFAULT_BASE_URL,
            CINS_DEFAULT_MIN_REFRESH_INTERVAL,
            runtime(),
        );

        assert_eq!(provider.url(), format!("https://cinsscore.com/{LIST_PATH}"));
    }

    #[test]
    fn a_header_line_is_kept_verbatim() {
        let list = parse_list("# CINS Army list\n45.32.1.1\n", now()).expect("the list is parsed");

        assert_eq!(list.header_lines, vec!["CINS Army list".to_string()]);
    }

    #[test]
    fn an_empty_line_names_no_address() {
        let list = parse_list("45.32.1.1\n\n45.32.1.2\n", now()).expect("the list is parsed");

        assert_eq!(list.entries.len(), 2);
    }

    #[test]
    fn an_address_is_an_observation() {
        let list = parse_list("45.32.1.1\n", now()).expect("the list is parsed");

        assert_eq!(list.entries.len(), 1);
        assert_eq!(
            list.entries[0].upstream_values.get("address"),
            Some(&"45.32.1.1".to_string())
        );
    }

    #[test]
    fn a_token_that_holds_a_prefix_is_dropped() {
        let addresses: Vec<String> = addresses_of("45.32.1.1 45.32.1.0/24 45.32.1.2")
            .map(|address| address.to_string())
            .collect();

        assert_eq!(addresses, vec!["45.32.1.1", "45.32.1.2"]);
    }

    #[test]
    fn a_token_that_is_no_address_is_dropped() {
        let addresses: Vec<_> = addresses_of("not-an-address 999.1.1.1").collect();

        assert!(addresses.is_empty());
    }

    #[test]
    fn a_token_that_holds_two_addresses_is_dropped() {
        let addresses: Vec<_> = addresses_of("45.32.1.1345.32.1.14").collect();

        assert!(addresses.is_empty());
    }

    #[test]
    fn an_empty_body_is_a_parse_error() {
        assert!(matches!(
            parse_list("", now()),
            Err(crate::error::ProviderError::Parse(_))
        ));
    }

    #[test]
    fn a_body_that_names_no_address_is_a_parse_error() {
        assert!(matches!(
            parse_list("# only a header\nnot-an-address\n", now()),
            Err(crate::error::ProviderError::Parse(_))
        ));
    }
}
