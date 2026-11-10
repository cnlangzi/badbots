//! The data model of the library.

pub mod classification;
pub mod evidence;
pub mod ip;
pub mod request_signals;

pub use classification::{
    Classification, Coverage, CoverageLevel, IpVerdict, VerdictInput, VerdictReason,
};
pub use evidence::{
    Assertion, BehaviorIntent, Evidence, EvidenceStrength, MatchScope, ObservationWindow,
    ProviderId, SourceFamily, Suppression, ThreatCategory,
};
pub use ip::{is_assessable, network_contains, normalize};
pub use request_signals::{
    BotKind, BotVerdict, RequestVerdict, UaState, UserAgentMarkers, classify_user_agent,
    is_well_formed_user_agent, ua_state,
};
