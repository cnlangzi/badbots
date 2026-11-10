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
