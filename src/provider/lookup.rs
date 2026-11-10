//! The plumbing every lookup provider shares.
//!
//! A lookup is bounded by a timeout, counted against the local budget guard and
//! limited by the per-provider rate limiter. A provider that answers with
//! `429 Too Many Requests` is put into cooldown instead of being retried.

use std::time::Duration;

use time::OffsetDateTime;

use crate::error::ProviderError;
use crate::http::{map_transport_error, parse_retry_after};
use crate::quota::{QuotaGuard, QuotaWindow};
use crate::ratelimit::{Cooldown, TokenBucket};

/// The cooldown a provider enters when it does not advertise a `Retry-After`.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// The runtime a lookup provider performs its request in.
#[derive(Debug)]
pub struct ProviderRuntime {
    client: reqwest::Client,
    cooldown: Cooldown,
    quota: QuotaGuard,
    limiter: TokenBucket,
    timeout: Duration,
}

impl ProviderRuntime {
    /// Creates a runtime for one provider.
    pub fn new(client: reqwest::Client, quota: QuotaGuard, timeout: Duration) -> Self {
        Self {
            client,
            cooldown: Cooldown::new(),
            quota,
            limiter: TokenBucket::unlimited(),
            timeout,
        }
    }

    /// The budget guard of the provider.
    pub fn quota(&self) -> &QuotaGuard {
        &self.quota
    }

    /// The HTTP client of the provider.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The cooldown of the provider.
    pub fn cooldown(&self) -> &Cooldown {
        &self.cooldown
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
        if let Some(remaining) = self.cooldown.remaining() {
            return Err(ProviderError::RateLimited {
                retry_after: Some(remaining),
            });
        }

        if !self.quota.try_consume(now) {
            return Err(ProviderError::QuotaExhausted);
        }

        if !self.limiter.try_acquire() {
            return Err(ProviderError::RateLimited { retry_after: None });
        }

        let response = tokio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|error| map_transport_error(&error))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
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
}

/// Reads the body of a successful response.
pub async fn read_body(response: reqwest::Response) -> Result<String, ProviderError> {
    response
        .text()
        .await
        .map_err(|error| map_transport_error(&error))
}

/// Parses a JSON body.
pub fn parse_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, ProviderError> {
    serde_json::from_str(body).map_err(|error| ProviderError::Parse(error.to_string()))
}

/// The budget guard of a provider that is counted per day.
pub fn daily_guard(limit: u32) -> QuotaGuard {
    QuotaGuard::new(limit, QuotaWindow::Day)
}

/// The budget guard of a provider that is counted per month.
pub fn monthly_guard(limit: u32) -> QuotaGuard {
    QuotaGuard::new(limit, QuotaWindow::Month)
}
