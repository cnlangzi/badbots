//! The live checks of the providers the crate ships.
//!
//! Every test in this file contacts the real upstream of one provider, so the
//! tests are marked `#[ignore]` and an ordinary test run never touches the
//! network. The daily health check of the repository runs them with
//! `cargo test --all-features --test live_providers -- --ignored`.
//!
//! Every test writes its outcome into `target/provider-health/report.json`
//! before it fails, so that the report of a red run names every provider that
//! broke.

#![allow(dead_code)]

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use badbots::{BadBots, BlocklistDeConfig, Config, ProviderError, ProviderId};
use serde::Serialize;
use time::OffsetDateTime;

/// The timeout of a single request of the check.
///
/// The default timeout of the library is five seconds, which is tight for the
/// larger lists.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a published list may be old.
const MAX_LIST_AGE: time::Duration = time::Duration::days(7);

/// The environment variable that carries the AbuseIPDB credential.
const ABUSEIPDB_API_KEY_ENV: &str = "BADBOTS_ABUSEIPDB_API_KEY";

/// The environment variable that carries the CrowdSec credential.
const CROWDSEC_API_KEY_ENV: &str = "BADBOTS_CROWDSEC_API_KEY";

/// The environment variable that replaces the address of the AbuseIPDB check.
const ABUSEIPDB_PROBE_ENV: &str = "BADBOTS_PROBE_IP_ABUSEIPDB";

/// The environment variable that replaces the address of the CrowdSec check.
const CROWDSEC_PROBE_ENV: &str = "BADBOTS_PROBE_IP_CROWDSEC";

/// The environment variable that replaces the address of the Blocklist.de
/// check.
const BLOCKLIST_DE_PROBE_ENV: &str = "BADBOTS_PROBE_IP_BLOCKLIST_DE";

/// The address the AbuseIPDB check asks about.
///
/// The upstream answers every public address, so an address without a
/// reputation is enough to prove that the provider answers.
const ABUSEIPDB_PROBE: &str = "8.8.8.8";

/// The address the CrowdSec check asks about.
///
/// The CTI answers an address it holds no data for with `404`, so the address
/// has to be one the CTI knows. It is an address that the published attack
/// lists name as an active scanner. The address can be replaced through
/// [`CROWDSEC_PROBE_ENV`].
const CROWDSEC_PROBE: &str = "71.6.146.185";

/// The address the Blocklist.de check asks about.
///
/// The upstream answers every public address, so an address without a
/// reputation is enough to prove that the provider answers.
const BLOCKLIST_DE_PROBE: &str = "8.8.8.8";

/// The report of the check.
#[derive(Serialize)]
struct Report {
    /// The outcome of every provider.
    providers: Vec<Entry>,
}

/// The outcome of one provider.
#[derive(Clone, Serialize)]
struct Entry {
    /// The provider.
    provider: String,
    /// The status of the check of the provider.
    status: String,
    /// What the check found.
    detail: String,
}

/// The outcome of the check of one provider.
enum Outcome {
    /// The provider answered and its answer is usable.
    Healthy(String),
    /// The provider did not answer or its answer is not usable.
    Broken(String),
    /// The provider was not checked because it lacks a credential.
    Skipped(String),
}

impl Outcome {
    /// The status the report carries.
    fn status(&self) -> &'static str {
        match self {
            Outcome::Healthy(_) => "ok",
            Outcome::Broken(_) => "failed",
            Outcome::Skipped(_) => "skipped",
        }
    }

    /// The detail the report carries.
    fn detail(&self) -> &str {
        match self {
            Outcome::Healthy(detail) | Outcome::Broken(detail) | Outcome::Skipped(detail) => detail,
        }
    }
}

/// The outcomes the check recorded so far.
///
/// The tests of one run are the threads of one process, so the report is
/// written under a lock.
static ENTRIES: Mutex<Vec<Entry>> = Mutex::new(Vec::new());

/// Records the outcome of a provider and rewrites the report.
fn record(entry: Entry) {
    let mut entries = ENTRIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.push(entry);
    write_report(&entries);
}

/// Writes the report of the check.
fn write_report(entries: &[Entry]) {
    let path = report_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("the report directory is created");
    }

    let report = Report {
        providers: entries.to_vec(),
    };
    let body = serde_json::to_string_pretty(&report).expect("the report is serializable");
    fs::write(&path, body).expect("the report is written");
}

/// The path of the report.
///
/// The path is fixed, so that the workflow of the repository finds the report
/// where it reads it.
fn report_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("provider-health")
        .join("report.json")
}

/// Records the outcome of a provider and fails the test when it broke.
fn finish(provider: &str, outcome: Outcome) {
    let status = outcome.status();
    let detail = outcome.detail();

    record(Entry {
        provider: provider.to_string(),
        status: status.to_string(),
        detail: detail.to_string(),
    });

    if status == "failed" {
        panic!("the {provider} check failed: {detail}");
    }
}

/// The credential the environment carries for a provider.
///
/// The library trims the value and treats an empty one as absent, so the check
/// does the same.
fn credential(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// The address a lookup check asks about.
///
/// The address can be replaced through the environment variable, so that a
/// provider that stops answering about the default address can still be
/// checked.
fn probe_address(name: &str, default: &str) -> Result<IpAddr, String> {
    let value = credential(name).unwrap_or_else(|| default.to_string());
    value
        .parse::<IpAddr>()
        .map_err(|error| format!("{value} is not an address: {error}"))
}

/// Asks a lookup provider about the probe address and checks its answer.
///
/// The instance holds exactly one provider, so the answer cannot come from
/// another one.
async fn check_lookup(
    provider: ProviderId,
    probe_env: &str,
    probe_default: &str,
    bots: BadBots,
) -> Outcome {
    let probe = match probe_address(probe_env, probe_default) {
        Ok(probe) => probe,
        Err(detail) => return Outcome::Broken(detail),
    };

    if !badbots::model::is_assessable(probe) {
        return Outcome::Broken(format!("the probe address {probe} cannot be assessed"));
    }

    let verdict = bots.verify_ip(probe).await;

    if let Some((_, error)) = verdict
        .coverage
        .failed
        .iter()
        .find(|(id, _)| *id == provider)
    {
        return Outcome::Broken(failure_detail(error, probe_env));
    }

    let Some(status) = bots
        .provider_status()
        .into_iter()
        .find(|status| status.provider == provider)
    else {
        return Outcome::Broken("the provider reports no status".to_string());
    };

    if let Some(error) = &status.last_error {
        return Outcome::Broken(failure_detail(error, probe_env));
    }

    if status.last_attempt.is_none() {
        return Outcome::Broken(format!("the provider was never asked about {probe}"));
    }

    if !verdict.coverage.definitive.contains(&provider) {
        return Outcome::Broken("the answer of the provider is not definitive".to_string());
    }

    Outcome::Healthy(format!("the provider answered about {probe}"))
}

/// The detail of a failure of a lookup provider.
///
/// A `404` names an address the upstream holds no data for, which is a
/// property of the probe address rather than a broken provider.
fn failure_detail(error: &ProviderError, probe_env: &str) -> String {
    match error {
        ProviderError::Status { code: 404 } => format!(
            "the upstream holds no data for the probe address, replace it through {probe_env}"
        ),
        _ => format!("the upstream did not answer: {error}"),
    }
}

/// Refreshes the list of a feed provider and checks the snapshot.
///
/// The instance holds exactly one provider, so the list cannot come from
/// another one.
async fn check_feed(provider: ProviderId, bots: BadBots, published: bool) -> Outcome {
    let report = bots.refresh_feeds().await;

    let Some(result) = report
        .results
        .iter()
        .find(|result| result.provider == provider)
    else {
        return Outcome::Broken("the refresh did not ask the provider".to_string());
    };

    let snapshot = match &result.result {
        Ok(snapshot) => snapshot,
        Err(error) => return Outcome::Broken(format!("the list could not be fetched: {error}")),
    };

    if snapshot.entries.is_empty() {
        return Outcome::Broken("the list holds no address".to_string());
    }

    if published {
        let Some(published_at) = snapshot.published_at else {
            return Outcome::Broken("the list states no publication time".to_string());
        };

        if OffsetDateTime::now_utc() - published_at > MAX_LIST_AGE {
            return Outcome::Broken(format!("the list was published at {published_at}"));
        }
    }

    let Some(status) = bots
        .provider_status()
        .into_iter()
        .find(|status| status.provider == provider)
    else {
        return Outcome::Broken("the provider reports no status".to_string());
    };

    if let Some(error) = &status.last_error {
        return Outcome::Broken(format!("the provider recorded an error: {error}"));
    }

    if status.last_attempt.is_none() {
        return Outcome::Broken("the provider was never asked".to_string());
    }

    Outcome::Healthy(format!(
        "the list holds {} addresses",
        snapshot.entries.len()
    ))
}

/// The configuration of a Blocklist.de check that uses one of the two products
/// of the publisher.
fn blocklist_de_config(use_per_address_query: bool, use_service_lists: bool) -> Config {
    let mut config = Config::default();
    config.providers.blocklist_de = Some(BlocklistDeConfig {
        enabled: true,
        use_per_address_query,
        use_service_lists,
        ..BlocklistDeConfig::default()
    });
    config
}

/// Checks the AbuseIPDB provider.
#[cfg(feature = "abuseipdb")]
async fn check_abuseipdb() -> Outcome {
    if credential(ABUSEIPDB_API_KEY_ENV).is_none() {
        return Outcome::Skipped(format!("no credential in {ABUSEIPDB_API_KEY_ENV}"));
    }

    let bots = match BadBots::builder()
        .config(Config::default())
        .enable_abuseipdb()
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_lookup(
        ProviderId::ABUSEIPDB,
        ABUSEIPDB_PROBE_ENV,
        ABUSEIPDB_PROBE,
        bots,
    )
    .await
}

/// Checks the CrowdSec provider.
#[cfg(feature = "crowdsec")]
async fn check_crowdsec() -> Outcome {
    if credential(CROWDSEC_API_KEY_ENV).is_none() {
        return Outcome::Skipped(format!("no credential in {CROWDSEC_API_KEY_ENV}"));
    }

    let bots = match BadBots::builder()
        .config(Config::default())
        .enable_crowdsec()
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_lookup(
        ProviderId::CROWDSEC,
        CROWDSEC_PROBE_ENV,
        CROWDSEC_PROBE,
        bots,
    )
    .await
}

/// Checks the per-address query of Blocklist.de.
#[cfg(feature = "blocklist_de")]
async fn check_blocklist_de() -> Outcome {
    let bots = match BadBots::builder()
        .config(blocklist_de_config(true, false))
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_lookup(
        ProviderId::BLOCKLIST_DE,
        BLOCKLIST_DE_PROBE_ENV,
        BLOCKLIST_DE_PROBE,
        bots,
    )
    .await
}

/// Checks the service lists of Blocklist.de.
#[cfg(feature = "blocklist_de")]
async fn check_blocklist_de_lists() -> Outcome {
    let bots = match BadBots::builder()
        .config(blocklist_de_config(false, true))
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_feed(ProviderId::BLOCKLIST_DE_LISTS, bots, false).await
}

/// Checks the Spamhaus provider.
#[cfg(feature = "spamhaus")]
async fn check_spamhaus() -> Outcome {
    let bots = match BadBots::builder()
        .config(Config::default())
        .enable_spamhaus()
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_feed(ProviderId::SPAMHAUS, bots, true).await
}

/// Checks the DShield provider.
#[cfg(feature = "dshield")]
async fn check_dshield() -> Outcome {
    let bots = match BadBots::builder()
        .config(Config::default())
        .enable_dshield()
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_feed(ProviderId::DSHIELD, bots, true).await
}

/// Checks the steeman provider.
#[cfg(feature = "steeman")]
async fn check_steeman() -> Outcome {
    let bots = match BadBots::builder()
        .config(Config::default())
        .enable_steeman()
        .request_timeout(REQUEST_TIMEOUT)
        .build()
    {
        Ok(bots) => bots,
        Err(error) => return Outcome::Broken(format!("the library was not built: {error}")),
    };

    check_feed(ProviderId::STEEMAN, bots, true).await
}

/// The AbuseIPDB provider answers about the probe address.
#[cfg(feature = "abuseipdb")]
#[tokio::test]
#[ignore = "contacts the live AbuseIPDB upstream"]
async fn the_abuseipdb_provider_answers_about_the_probe_address() {
    finish(ProviderId::ABUSEIPDB.as_str(), check_abuseipdb().await);
}

/// The CrowdSec provider answers about the probe address.
#[cfg(feature = "crowdsec")]
#[tokio::test]
#[ignore = "contacts the live CrowdSec upstream"]
async fn the_crowdsec_provider_answers_about_the_probe_address() {
    finish(ProviderId::CROWDSEC.as_str(), check_crowdsec().await);
}

/// The per-address query of Blocklist.de answers about the probe address.
#[cfg(feature = "blocklist_de")]
#[tokio::test]
#[ignore = "contacts the live Blocklist.de upstream"]
async fn the_blocklist_de_query_answers_about_the_probe_address() {
    finish(
        ProviderId::BLOCKLIST_DE.as_str(),
        check_blocklist_de().await,
    );
}

/// The service lists of Blocklist.de are fetched.
#[cfg(feature = "blocklist_de")]
#[tokio::test]
#[ignore = "contacts the live Blocklist.de upstream"]
async fn the_blocklist_de_lists_are_fetched() {
    finish(
        ProviderId::BLOCKLIST_DE_LISTS.as_str(),
        check_blocklist_de_lists().await,
    );
}

/// The Spamhaus lists are fetched.
#[cfg(feature = "spamhaus")]
#[tokio::test]
#[ignore = "contacts the live Spamhaus upstream"]
async fn the_spamhaus_lists_are_fetched() {
    finish(ProviderId::SPAMHAUS.as_str(), check_spamhaus().await);
}

/// The DShield lists are fetched.
#[cfg(feature = "dshield")]
#[tokio::test]
#[ignore = "contacts the live DShield upstream"]
async fn the_dshield_lists_are_fetched() {
    finish(ProviderId::DSHIELD.as_str(), check_dshield().await);
}

/// The steeman list is fetched.
#[cfg(feature = "steeman")]
#[tokio::test]
#[ignore = "contacts the live steeman upstream"]
async fn the_steeman_list_is_fetched() {
    finish(ProviderId::STEEMAN.as_str(), check_steeman().await);
}
