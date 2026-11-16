//! The document every provider of the crate asks for.

#[cfg(feature = "abuseipdb")]
#[test]
fn the_abuseipdb_provider_asks_for_a_json_document() {
    assert_eq!(
        badbots::provider::abuseipdb::AbuseIpdbProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Json
    );
}

#[cfg(feature = "crowdsec")]
#[test]
fn the_crowdsec_provider_asks_for_a_json_document() {
    assert_eq!(
        badbots::provider::crowdsec::CrowdSecProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Json
    );
}

#[cfg(feature = "blocklist_de")]
#[test]
fn the_blocklist_de_query_provider_asks_for_a_json_document() {
    assert_eq!(
        badbots::provider::blocklist_de::BlocklistDeQueryProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Json
    );
}

#[cfg(feature = "blocklist_de")]
#[test]
fn the_blocklist_de_list_provider_asks_for_a_text_document() {
    assert_eq!(
        badbots::provider::blocklist_de::BlocklistDeListProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Text
    );
}

#[cfg(feature = "spamhaus")]
#[test]
fn the_spamhaus_provider_asks_for_a_json_document() {
    assert_eq!(
        badbots::provider::spamhaus::SpamhausProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Json
    );
}

#[cfg(feature = "dshield")]
#[test]
fn the_dshield_provider_asks_for_a_text_document() {
    assert_eq!(
        badbots::provider::dshield::DShieldProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Text
    );
}

#[cfg(feature = "steeman")]
#[test]
fn the_steeman_provider_asks_for_a_text_document() {
    assert_eq!(
        badbots::provider::steeman::SteemanProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Text
    );
}

#[cfg(feature = "cins")]
#[test]
fn the_cins_provider_asks_for_a_text_document() {
    assert_eq!(
        badbots::provider::cins::CinsProvider::DOCUMENT_KIND,
        badbots::DocumentKind::Text
    );
}
