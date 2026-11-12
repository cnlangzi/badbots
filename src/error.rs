//! Error types for configuration and provider interactions.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::ProviderId;

/// Failure of a single provider interaction.
///
/// The variant carries no HTTP client types so that the error type stays available
/// when the provider features are compiled out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ProviderError {
    /// The provider was not given the credentials or settings it needs.
    #[error("provider is not configured")]
    NotConfigured,
    /// The provider rejected the API key.
    #[error("provider rejected the credentials")]
    Unauthorized,
    /// The provider is rate limiting; `retry_after` is the upstream `Retry-After` hint.
    #[error("provider rate limited the request (retry after {retry_after:?})")]
    RateLimited {
        /// Duration the provider asked the caller to wait, when it advertised one.
        retry_after: Option<Duration>,
    },
    /// The request did not complete within the configured timeout.
    #[error("provider request timed out")]
    Timeout,
    /// The request failed at the transport layer.
    #[error("transport error: {0}")]
    Transport(String),
    /// The provider answered with an unexpected status code.
    #[error("provider returned status {code}")]
    Status {
        /// The HTTP status code.
        code: u16,
    },
    /// The provider answer could not be interpreted.
    #[error("provider response could not be parsed: {0}")]
    Parse(String),
    /// The local budget guard for the current window is used up.
    #[error("provider quota exhausted")]
    QuotaExhausted,
}

/// Configuration problem detected while building the library.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A provider was enabled without the API key it needs.
    #[error("missing api key for provider {provider}")]
    MissingApiKey {
        /// The provider that lacks credentials.
        provider: ProviderId,
    },
    /// A provider was configured but its crate feature was not compiled in.
    #[error("provider {provider} requires the crate feature `{feature}`")]
    MissingFeature {
        /// The provider whose feature is missing.
        provider: ProviderId,
        /// The Cargo feature that has to be enabled.
        feature: &'static str,
    },
    /// The configuration is otherwise unusable.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}
