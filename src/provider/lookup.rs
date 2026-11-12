//! The plumbing every lookup provider shares.
//!
//! A lookup is bounded by a timeout and counted against the local budget guard.
//! A provider that answers with `429 Too Many Requests` is put into cooldown
//! instead of being retried.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::clock::Clock;
use crate::error::ProviderError;
use crate::http::{map_transport_error, parse_retry_after};
use crate::quota::Quota;
use crate::ratelimit::Cooldown;

/// The cooldown a provider enters when it does not advertise a `Retry-After`.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// The runtime a lookup provider performs its request in.
pub struct ProviderRuntime {
    client: reqwest::Client,
    cooldown: Cooldown,
    quota: Arc<dyn Quota>,
    timeout: Duration,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for ProviderRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderRuntime")
            .field("cooldown", &self.cooldown)
            .field("quota_limit", &self.quota.bounded_limit())
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ProviderRuntime {
    /// Creates a runtime for one provider.
    pub fn new(
        client: reqwest::Client,
        quota: Arc<dyn Quota>,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            client,
            cooldown: Cooldown::new(),
            quota,
            timeout,
            clock,
        }
    }

    /// The budget of the provider.
    pub fn quota(&self) -> &dyn Quota {
        self.quota.as_ref()
    }

    /// The HTTP client of the provider.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The cooldown of the provider.
    pub fn cooldown(&self) -> &Cooldown {
        &self.cooldown
    }

    /// The clock the provider reads the current time from.
    pub fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }

    /// Sends a request and returns the successful response.
    ///
    /// The request is not issued when the provider is cooling down or when the
    /// budget of the current window is used up.
    pub async fn send(
        &self,
        request: reqwest::RequestBuilder,
        now: OffsetDateTime,
    ) -> Result<reqwest::Response, ProviderError> {
        self.dispatch(request, now, true).await
    }

    /// Sends a request that carries no credentials.
    ///
    /// A published list and the per-address query of Blocklist.de are read
    /// without a key, so a refused request is reported with its status code
    /// rather than as an authentication failure.
    pub async fn send_anonymous(
        &self,
        request: reqwest::RequestBuilder,
        now: OffsetDateTime,
    ) -> Result<reqwest::Response, ProviderError> {
        self.dispatch(request, now, false).await
    }

    async fn dispatch(
        &self,
        request: reqwest::RequestBuilder,
        now: OffsetDateTime,
        refused_is_unauthorized: bool,
    ) -> Result<reqwest::Response, ProviderError> {
        if let Some(remaining) = self.cooldown.remaining() {
            return Err(ProviderError::RateLimited {
                retry_after: Some(remaining),
            });
        }

        if !self.quota.try_consume(now) {
            return Err(ProviderError::QuotaExhausted);
        }

        let response = tokio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|error| map_transport_error(&error))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ProviderError::Unauthorized);
        }

        if refused_is_unauthorized && status == reqwest::StatusCode::FORBIDDEN {
            return Err(ProviderError::Unauthorized);
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = parse_retry_after(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
            );
            let cooldown = retry_after.unwrap_or(DEFAULT_COOLDOWN);
            self.cooldown.enter(cooldown);
            return Err(ProviderError::RateLimited { retry_after });
        }

        Err(ProviderError::Status {
            code: status.as_u16(),
        })
    }

    /// Reads the body of a successful response.
    ///
    /// The read is bounded by the same timeout as the request, so a response
    /// that delivers its headers and then stalls cannot hold a lookup open.
    pub async fn read_body(&self, response: reqwest::Response) -> Result<String, ProviderError> {
        tokio::time::timeout(self.timeout, response.text())
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|error| map_transport_error(&error))
    }
}

/// Parses a JSON body.
pub fn parse_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, ProviderError> {
    serde_json::from_str(body).map_err(|error| ProviderError::Parse(error.to_string()))
}
