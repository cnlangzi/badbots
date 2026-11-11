//! The configuration surface of the library.

use std::time::Duration;

use badbots::{
    AbuseIpdbConfig, ApiKey, BadBots, BlocklistDeConfig, Classification, Config, ConfigError,
    Coverage, CoverageLevel, DShieldConfig, Evidence, EvidenceStrength, MatchScope,
    NetworkScopePolicy, ProviderId, SourceFamily, SpamhausConfig, Suppression, ThreatCategory,
    VerdictInput, VerdictReason,
};
use time::OffsetDateTime;

#[test]
fn the_default_configuration_carries_the_documented_values() {
    let config = Config::default();

    assert_eq!(config.request_timeout, Duration::from_secs(5));
    assert_eq!(config.positive_ttl, Duration::from_secs(30 * 24 * 60 * 60));
    assert_eq!(config.negative_ttl, Duration::from_secs(24 * 60 * 60));
    assert_eq!(config.failure_ttl, Duration::from_secs(5 * 60));
    assert_eq!(
        config.network_scope_policy,
        NetworkScopePolicy::CorroborateOnly
    );
    assert_eq!(config.max_concurrent_enrichments, 4);
    assert_eq!(config.cache_capacity, 10_000);
}

#[test]
fn a_configuration_survives_a_serde_round_trip() {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("test-key")),
        daily_quota: Some(500),
        base_url: Some("https://example.test/api/v2".to_string()),
        max_age_days: Some(30),
    });
    config.providers.spamhaus = Some(SpamhausConfig {
        enabled: true,
        min_refresh_interval: Some(Duration::from_secs(3600)),
        base_url: Some("https://example.test/drop".to_string()),
    });
    config.providers.blocklist_de = Some(BlocklistDeConfig {
        enabled: true,
        window: Some(Duration::from_secs(3600)),
        min_refresh_interval: Some(Duration::from_secs(1800)),
        use_per_address_query: false,
        use_service_lists: true,
        daily_quota: Some(100),
        api_base_url: Some("https://example.test".to_string()),
        lists_base_url: Some("https://lists.example.test".to_string()),
    });
    config.providers.dshield = Some(DShieldConfig {
        enabled: true,
        min_refresh_interval: Some(Duration::from_secs(3600)),
        user_agent: Some("badbots/0.1.0".to_string()),
        base_url: Some("https://feeds.example.test".to_string()),
    });

    let encoded = serde_json::to_string(&config).expect("the configuration is encoded");
    let decoded: Config = serde_json::from_str(&encoded).expect("the configuration is decoded");

    assert_eq!(decoded, config);
}

#[test]
fn the_list_providers_keep_their_documented_defaults() {
    let decoded: Config =
        serde_json::from_str("{\"providers\":{\"blocklist_de\":{\"enabled\":true}}}").unwrap();

    let provider = decoded
        .providers
        .blocklist_de
        .expect("the provider is configured");
    assert!(provider.use_per_address_query);
    assert!(provider.use_service_lists);
}

#[test]
fn a_partial_configuration_is_decoded() {
    let decoded: Config =
        serde_json::from_str("{\"providers\":{\"abuseipdb\":{\"enabled\":true}}}").unwrap();

    assert!(decoded.providers.abuseipdb_enabled());
    assert_eq!(decoded.request_timeout, Duration::from_secs(5));
}

#[test]
fn a_provider_without_a_key_is_reported() {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        ..AbuseIpdbConfig::default()
    });

    let error = BadBots::builder()
        .config(config)
        .build()
        .expect_err("the provider has no key");

    #[cfg(feature = "abuseipdb")]
    assert_eq!(
        error,
        ConfigError::MissingApiKey {
            provider: ProviderId::ABUSEIPDB
        }
    );

    #[cfg(not(feature = "abuseipdb"))]
    assert_eq!(
        error,
        ConfigError::MissingFeature {
            provider: ProviderId::ABUSEIPDB,
            feature: "abuseipdb",
        }
    );
}

#[test]
fn the_key_never_appears_in_the_debug_output() {
    let mut config = Config::default();
    config.providers.abuseipdb = Some(AbuseIpdbConfig {
        enabled: true,
        api_key: Some(ApiKey::new("super-secret-value")),
        ..AbuseIpdbConfig::default()
    });

    let rendered = format!("{config:?}");
    assert!(!rendered.contains("super-secret-value"));
    assert!(rendered.contains("redacted"));
}

fn evidence(family: &str, strength: EvidenceStrength) -> Evidence {
    Evidence {
        provider: ProviderId::new("provider"),
        family: SourceFamily::new(family.to_string()),
        assertion: badbots::Assertion::Attack,
        category: ThreatCategory::WebAttack,
        upstream_category: None,
        strength,
        scope: MatchScope::Exact,
        observed_at: None,
        published_at: None,
        retrieved_at: None,
        expires_at: None,
        observation_window: None,
        count: None,
        upstream_values: Default::default(),
    }
}

#[test]
fn the_classification_is_a_pure_function_of_its_input() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let input = VerdictInput {
        ip: "45.32.1.1".parse().unwrap(),
        evidence: vec![evidence("abuseipdb", EvidenceStrength::Convicting)],
        suppressions: vec![(ProviderId::new("provider"), Suppression::Benign)],
        coverage: Coverage::default(),
    };

    let first = badbots::classify(&input, &Config::default(), now);
    let second = badbots::classify(&input, &Config::default(), now);

    assert_eq!(first, second);
    assert_eq!(first.classification, Classification::Suspect);
    assert_eq!(first.reason, VerdictReason::EvidencePresent);
}

#[test]
fn a_consulted_provider_without_evidence_yields_no_evidence() {
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut coverage = Coverage::default();
    coverage.record_success(ProviderId::new("provider"), CoverageLevel::Definitive);

    let input = VerdictInput {
        ip: "45.32.1.1".parse().unwrap(),
        evidence: Vec::new(),
        suppressions: Vec::new(),
        coverage,
    };

    let verdict = badbots::classify(&input, &Config::default(), now);

    assert_eq!(verdict.classification, Classification::Unknown);
    assert_eq!(verdict.reason, VerdictReason::NoEvidence);
    assert_eq!(verdict.coverage.definitive.len(), 1);
}
