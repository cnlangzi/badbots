//! HTTP client construction and error mapping.

use std::time::Duration;

use crate::error::{ConfigError, ProviderError};

/// The user agent the library sends upstream.
pub fn user_agent() -> String {
    format!("badbots/{}", env!("CARGO_PKG_VERSION"))
}

/// Builds the HTTP client the library uses for provider lookups.
///
/// The client uses rustls, so the library builds without a system TLS stack.
pub fn build_client(timeout: Duration) -> Result<reqwest::Client, ConfigError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(user_agent())
        .build()
        .map_err(|error| ConfigError::Invalid(format!("http client could not be built: {error}")))
}

/// Maps a transport failure to a provider error.
pub fn map_transport_error(error: &reqwest::Error) -> ProviderError {
    if error.is_timeout() {
        ProviderError::Timeout
    } else {
        ProviderError::Transport(error.to_string())
    }
}

/// Parses a `Retry-After` header that carries a number of seconds.
pub fn parse_retry_after(value: Option<&str>) -> Option<Duration> {
    let seconds = value?.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds))
}
