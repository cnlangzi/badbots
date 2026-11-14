//! The steeman list provider.
//!
//! The upstream publishes the addresses his own intrusion detection systems
//! saw attacking. The observations come from the sensors of the publisher and
//! not from a redistribution of somebody else's feed, so they corroborate the
//! observations of the other providers.
//!
//! The provider is compiled in by the `steeman` crate feature. It expects no
//! credential: the list it reads is published for everyone. The publisher asks
//! for no more than two downloads a day, so the provider waits a day between
//! two attempts.

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

/// The file name of the list of the addresses that were seen attacking.
pub const LEVEL2_FILE: &str = "Level2_IP_Block_List.txt";

/// The time an observation of the list stays usable.
pub const VALIDITY: time::Duration = time::Duration::hours(48);

/// The time a publication time may run ahead of the retrieval.
///
/// The clock of the publisher may run ahead of the clock of the host, so a
/// list may name a publication time that lies after the moment it was fetched.
const PUBLICATION_TOLERANCE: time::Duration = time::Duration::days(1);

/// The attribution the publisher asks for.
pub const ATTRIBUTION: &str = concat!(
    "IP block lists by Jeroen Steeman (https://www.steeman.org/IPBlock). ",
    "Free to use; updated daily; please do not download more than twice a day."
);

/// The steeman list provider.
pub struct SteemanProvider {
    base_url: String,
    min_refresh_interval: Duration,
    runtime: Arc<ProviderRuntime>,
}

impl SteemanProvider {
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
    fn url(&self, file: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), file)
    }
}

#[async_trait]
impl FeedProvider for SteemanProvider {
    fn id(&self) -> ProviderId {
        ProviderId::STEEMAN
    }

    fn family(&self) -> SourceFamily {
        SourceFamily::STEEMAN
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Corroborating
    }

    fn min_refresh_interval(&self) -> Duration {
        self.min_refresh_interval
    }

    async fn fetch(&self) -> Result<FeedSnapshot, ProviderError> {
        let now = self.runtime.clock().now();
        let request = self.runtime.client().get(self.url(LEVEL2_FILE));
        let response = self.runtime.send_anonymous(request, now).await?;
        let body = self.runtime.read_body(response).await?;
        let list = parse_list(&body, now)?;

        Ok(FeedSnapshot {
            provider: ProviderId::STEEMAN,
            family: SourceFamily::STEEMAN,
            published_at: list.published_at,
            retrieved_at: now,
            expires_at: Some(list.published_at.unwrap_or(now) + VALIDITY),
            attribution: ATTRIBUTION.to_string(),
            header_lines: list.header_lines,
            entries: list.entries,
        })
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

    let published_at = published_at_of(&header_lines, now);
    let expires_at = published_at.unwrap_or(now) + VALIDITY;

    let entries = addresses
        .into_iter()
        .map(|address| observation_for(address, published_at, expires_at, now))
        .collect();

    Ok(ParsedList {
        published_at,
        header_lines,
        entries,
    })
}

/// The addresses one data line names.
///
/// The publisher's file loses a line break now and then, so a line may hold
/// two addresses glued together, and a line may hold a range. A token that
/// carries a prefix is dropped, because the observation of a range belongs to
/// a source of ranges, and a token that does not parse is dropped, which
/// covers a glued pair as well: no address may ever be guessed.
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
/// The publisher does not say when he saw the address, so the observation
/// carries no observation time and the publication time of the list is the
/// only time it carries.
fn observation_for(
    address: IpAddr,
    published_at: Option<OffsetDateTime>,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Evidence {
    let mut upstream_values: BTreeMap<String, String> = BTreeMap::new();
    upstream_values.insert(ADDRESS_KEY.to_string(), address.to_string());

    Evidence {
        provider: ProviderId::STEEMAN,
        family: SourceFamily::STEEMAN,
        assertion: Assertion::Attack,
        category: ThreatCategory::GenericAbuse,
        upstream_category: None,
        strength: EvidenceStrength::Convicting,
        scope: MatchScope::Exact,
        observed_at: None,
        published_at,
        retrieved_at: Some(now),
        expires_at: Some(expires_at),
        observation_window: None,
        count: None,
        upstream_values,
    }
}

/// The publication time the header of the list carries.
///
/// The publisher names the publication time in the header of the list.
fn published_at_of(header_lines: &[String], now: OffsetDateTime) -> Option<OffsetDateTime> {
    header_lines.iter().rev().find_map(|line| {
        let position = find_update(line)?;
        let rest = line[position + "updated".len()..].trim();
        let rest = rest.strip_prefix(':').unwrap_or(rest).trim();
        parse_publication_time(rest, now)
    })
}

/// The position of the word that names the publication time.
fn find_update(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(6))
        .rfind(|&index| bytes[index..index + 7].eq_ignore_ascii_case(b"updated"))
}

/// The publication time the header states.
///
/// The publisher writes the time as `D/M/YYYY H:mm:ss UTC`. The hour is on a
/// twenty-four-hour clock, and the meridiem may be named, in which case the
/// hour is on a twelve-hour clock.
fn parse_publication_time(text: &str, now: OffsetDateTime) -> Option<OffsetDateTime> {
    let mut tokens = text.split_whitespace();

    let dates = parse_dates(tokens.next()?)?;
    let (hour, minute, second) = parse_clock(tokens.next()?)?;

    let mut meridiem = None;
    let mut zone = None;
    for token in tokens {
        match meridiem_of(token) {
            Some(period) => meridiem = Some(period),
            None => zone = Some(token),
        }
    }

    let hour = match meridiem {
        Some(meridiem) => hour_of_meridiem(hour, meridiem)?,
        None => hour,
    };

    let offset = match zone {
        Some(zone) => offset_of(zone)?,
        None => time::UtcOffset::UTC,
    };

    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    let limit = now + PUBLICATION_TOLERANCE;

    dates
        .into_iter()
        .map(|date| date.with_time(clock).assume_offset(offset))
        .filter(|published| *published <= limit)
        .max()
}

/// The dates the publisher states.
///
/// The publisher writes the date as `D/M/YYYY`. The day and the month are read
/// in either order, because the two orders name dates that lie a month apart
/// from each other, while the list is published every day and the date it
/// names lies close to the moment of the retrieval. A date that names no month
/// in one order is read in the other order alone.
fn parse_dates(text: &str) -> Option<Vec<time::Date>> {
    let mut parts = text.split('/');
    let first: u8 = parts.next()?.parse().ok()?;
    let second: u8 = parts.next()?.parse().ok()?;
    let year: i32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    let dates = [date_of(first, second, year), date_of(second, first, year)];
    Some(dates.into_iter().flatten().collect())
}

/// The calendar date a day and a month name.
fn date_of(day: u8, month: u8, year: i32) -> Option<time::Date> {
    let month = time::Month::try_from(month).ok()?;
    time::Date::from_calendar_date(year, month, day).ok()
}

/// The time of day the publisher states.
///
/// The publisher writes the time as `h:mm:ss`.
fn parse_clock(text: &str) -> Option<(u8, u8, u8)> {
    let mut parts = text.split(':');
    let hour = parts.next()?.parse().ok()?;
    let minute = parts.next()?.parse().ok()?;
    let second = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    Some((hour, minute, second))
}

/// The hour of the day the meridiem names.
///
/// The publisher writes the hour on a twelve-hour clock when it writes the
/// meridiem, so the meridiem decides whether the hour is in the afternoon.
fn hour_of_meridiem(hour: u8, meridiem: &str) -> Option<u8> {
    if !(1..=12).contains(&hour) {
        return None;
    }

    match meridiem {
        "AM" => Some(if hour == 12 { 0 } else { hour }),
        "PM" => Some(if hour == 12 { 12 } else { hour + 12 }),
        _ => None,
    }
}

/// The meridiem a token names, if it names one.
///
/// The case of the token does not matter.
fn meridiem_of(text: &str) -> Option<&'static str> {
    match text.to_ascii_uppercase().as_str() {
        "AM" => Some("AM"),
        "PM" => Some("PM"),
        _ => None,
    }
}

/// The offset the publisher states.
///
/// The publisher states the time in UTC.
fn offset_of(text: &str) -> Option<time::UtcOffset> {
    match text.to_ascii_uppercase().as_str() {
        "UTC" | "GMT" | "Z" => Some(time::UtcOffset::UTC),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use time::OffsetDateTime;
    use time::macros::datetime;

    use super::{
        LEVEL2_FILE, SteemanProvider, addresses_of, parse_publication_time, published_at_of,
    };
    use crate::config::{STEEMAN_DEFAULT_BASE_URL, STEEMAN_DEFAULT_MIN_REFRESH_INTERVAL};
    use crate::provider::lookup::ProviderRuntime;
    use crate::quota::daily_guard;

    /// The moment the list is read at.
    fn now() -> OffsetDateTime {
        datetime!(2026-11-14 12:00:00 UTC)
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
    fn the_default_base_url_names_the_level2_list() {
        let provider = SteemanProvider::new(
            STEEMAN_DEFAULT_BASE_URL,
            STEEMAN_DEFAULT_MIN_REFRESH_INTERVAL,
            runtime(),
        );

        assert_eq!(
            provider.url(LEVEL2_FILE),
            "https://www.steeman.org/Level2_IP_Block_List.txt"
        );
    }

    #[test]
    fn the_publication_time_is_read_from_the_header() {
        let header = "https://jeroen.steeman.org/Level2_IP_Block_List.txt Contains 16469 IP \
                      addresses. Last updated: 14/11/2026 03:52:24 UTC";

        assert_eq!(
            published_at_of(&[header.to_string()], now()),
            Some(datetime!(2026-11-14 03:52:24 UTC))
        );
    }

    #[test]
    fn the_publication_time_is_read_from_a_header_of_several_lines() {
        let header = vec![
            "https://jeroen.steeman.org/Level2_IP_Block_List.txt".to_string(),
            "Contains 16469 IP addresses.".to_string(),
            "Last updated: 14/11/2026 03:52:24 UTC".to_string(),
        ];

        assert_eq!(
            published_at_of(&header, now()),
            Some(datetime!(2026-11-14 03:52:24 UTC))
        );
    }

    #[test]
    fn a_header_without_a_time_carries_no_publication_time() {
        let header = vec!["https://jeroen.steeman.org/Level2_IP_Block_List.txt".to_string()];

        assert_eq!(published_at_of(&header, now()), None);
    }

    #[test]
    fn the_hour_may_have_one_digit() {
        assert_eq!(
            parse_publication_time("14/11/2026 3:52:24 UTC", now()),
            Some(datetime!(2026-11-14 03:52:24 UTC))
        );
    }

    #[test]
    fn the_hour_may_have_two_digits() {
        assert_eq!(
            parse_publication_time("14/11/2026 03:52:24 UTC", now()),
            Some(datetime!(2026-11-14 03:52:24 UTC))
        );
    }

    #[test]
    fn the_meridiem_may_be_absent() {
        assert_eq!(
            parse_publication_time("14/11/2026 19:25:57 UTC", now()),
            Some(datetime!(2026-11-14 19:25:57 UTC))
        );
    }

    #[test]
    fn the_midnight_and_noon_of_the_meridiem_are_read() {
        assert_eq!(
            parse_publication_time("5/13/2026 12:25:57 AM UTC", now()),
            Some(datetime!(2026-05-13 00:25:57 UTC))
        );
        assert_eq!(
            parse_publication_time("5/13/2026 12:25:57 PM UTC", now()),
            Some(datetime!(2026-05-13 12:25:57 UTC))
        );
    }

    #[test]
    fn the_day_and_the_month_are_read_in_either_order() {
        assert_eq!(
            parse_publication_time("12/11/2026 03:52:24 UTC", now()),
            Some(datetime!(2026-11-12 03:52:24 UTC))
        );
        assert_eq!(
            parse_publication_time("5/13/2026 03:52:24 UTC", now()),
            Some(datetime!(2026-05-13 03:52:24 UTC))
        );
    }

    #[test]
    fn a_date_that_names_both_orders_is_the_later_of_the_two() {
        assert_eq!(
            parse_publication_time("05/11/2026 03:52:24 UTC", now()),
            Some(datetime!(2026-11-05 03:52:24 UTC))
        );
    }

    #[test]
    fn a_date_that_does_not_depend_on_the_clock_of_the_host() {
        let later = datetime!(2027-05-20 12:00:00 UTC);

        assert_eq!(
            parse_publication_time("05/11/2026 03:52:24 UTC", later),
            Some(datetime!(2026-11-05 03:52:24 UTC))
        );
    }

    #[test]
    fn a_date_that_lies_after_the_retrieval_is_dropped() {
        let later = datetime!(2026-12-01 12:00:00 UTC);

        assert_eq!(
            parse_publication_time("12/11/2026 03:52:24 UTC", later),
            Some(datetime!(2026-11-12 03:52:24 UTC))
        );
    }

    #[test]
    fn a_date_that_lies_after_the_retrieval_in_both_orders_is_no_publication_time() {
        let earlier = datetime!(2026-01-01 12:00:00 UTC);

        assert_eq!(
            parse_publication_time("12/11/2026 03:52:24 UTC", earlier),
            None
        );
    }

    #[test]
    fn a_time_that_cannot_be_read_is_no_publication_time() {
        assert_eq!(parse_publication_time("the 13th of May", now()), None);
        assert_eq!(parse_publication_time("5/13/2026 7:25:57 CET", now()), None);
        assert_eq!(
            parse_publication_time("5/13/2026 25:25:57 PM UTC", now()),
            None
        );
    }

    #[test]
    fn a_token_that_holds_a_range_is_dropped() {
        let addresses: Vec<String> = addresses_of("45.32.1.1 45.32.1.0/24 45.32.1.2")
            .map(|address| address.to_string())
            .collect();

        assert_eq!(addresses, vec!["45.32.1.1", "45.32.1.2"]);
    }

    #[test]
    fn a_token_that_holds_two_addresses_is_dropped() {
        let addresses: Vec<_> = addresses_of("45.32.1.1345.32.1.14").collect();

        assert!(addresses.is_empty());
    }

    #[test]
    fn a_token_that_is_no_address_is_dropped() {
        let addresses: Vec<_> = addresses_of("not-an-address 999.1.1.1").collect();

        assert!(addresses.is_empty());
    }
}
