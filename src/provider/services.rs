//! The services a published list names.
//!
//! The publishers name the same services in different ways: Blocklist.de names
//! them, and DShield names some of them by the port they serve. The table
//! maps a service to the claim and the threat category of the activity it
//! stands for.

use crate::model::{Assertion, ThreatCategory};

/// The services a list may name.
pub const SERVICES: &[&str] = &[
    "all",
    "ssh",
    "apache",
    "imap",
    "ftp",
    "sip",
    "bots",
    "bruteforcelogin",
    "strongips",
];

/// The kind of activity a service stands for.
pub fn category_of(service: &str) -> ThreatCategory {
    match service {
        "ssh" | "imap" | "ftp" | "sip" | "bruteforcelogin" => ThreatCategory::BruteForce,
        "apache" => ThreatCategory::WebAttack,
        "mail" => ThreatCategory::SpamAbuse,
        _ => ThreatCategory::GenericAbuse,
    }
}

/// The claim a service makes about the address it lists.
///
/// A service that names one kind of activity claims that the address
/// committed an attack. A list that names several kinds of activity claims
/// less, because the publisher does not say which kind it was.
pub fn assertion_of(service: &str) -> Assertion {
    match service {
        "ssh" | "imap" | "ftp" | "sip" | "bruteforcelogin" | "apache" => Assertion::Attack,
        _ => Assertion::Abuse,
    }
}
