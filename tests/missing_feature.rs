//! The behaviour of a provider whose crate feature is not compiled in.

#![cfg(not(feature = "abuseipdb"))]

use badbots::{AbuseIpdbConfig, ApiKey, BadBots, Config, ConfigError, ProviderId};

#[test]
fn a_provider_without_its_feature_is_reported() {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("test-key")),
        daily_quota: None,
        base_url: None,
        max_age_days: None,
    });

    let error = BadBots::builder()
        .config(config)
        .build()
        .expect_err("the provider feature is missing");

    assert_eq!(
        error,
        ConfigError::MissingFeature {
            provider: ProviderId::ABUSEIPDB,
            feature: "abuseipdb",
        }
    );
}

#[cfg(not(feature = "spamhaus"))]
#[test]
fn the_spamhaus_provider_without_its_feature_is_reported() {
    let error = BadBots::builder()
        .enable_spamhaus()
        .build()
        .expect_err("the provider feature is missing");

    assert_eq!(
        error,
        ConfigError::MissingFeature {
            provider: ProviderId::SPAMHAUS,
            feature: "spamhaus",
        }
    );
}

#[cfg(not(feature = "blocklist_de"))]
#[test]
fn the_blocklist_de_provider_without_its_feature_is_reported() {
    let error = BadBots::builder()
        .enable_blocklist_de()
        .build()
        .expect_err("the provider feature is missing");

    assert_eq!(
        error,
        ConfigError::MissingFeature {
            provider: ProviderId::BLOCKLIST_DE,
            feature: "blocklist_de",
        }
    );
}

#[cfg(not(feature = "dshield"))]
#[test]
fn the_dshield_provider_without_its_feature_is_reported() {
    let error = BadBots::builder()
        .enable_dshield()
        .build()
        .expect_err("the provider feature is missing");

    assert_eq!(
        error,
        ConfigError::MissingFeature {
            provider: ProviderId::DSHIELD,
            feature: "dshield",
        }
    );
}
