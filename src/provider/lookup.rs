//! The plumbing every lookup provider shares.
//!
//! A lookup is bounded by a timeout and counted against the local budget guard.
//! A provider that answers with `429 Too Many Requests` is put into cooldown
//! instead of being retried.
//!
//! The runtime also recovers a refused document. An answer that is not the
//! document of the publisher is repeated over the other address family, and
//! the family that delivered the document is remembered for the host, so the
//! next request to that host does not pay for the refusal again.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use time::OffsetDateTime;

use crate::clock::Clock;
use crate::error::ProviderError;
use crate::http::{AddressFamily, ClientSet, map_transport_error, parse_retry_after};
use crate::model::ProviderId;
use crate::quota::Quota;
use crate::ratelimit::Cooldown;

/// The cooldown a provider enters when it does not advertise a `Retry-After`.
pub const DEFAULT_COOLDOWN: Duration = Duration::from_secs(60);

/// The number of bytes an excerpt of a body holds.
pub const EXCERPT_LIMIT: usize = 64;

/// The kind of document a provider asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentKind {
    /// A document of JSON values.
    Json,
    /// A list of addresses in a text document.
    Text,
}

/// The verdict of the library about the status of an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The answer carries the document.
    Document,
    /// The answer is not the document.
    ///
    /// The request may be repeated over the other address family.
    Refusal,
    /// The upstream answered with a status it decides itself.
    ///
    /// The status is the status of the answer.
    Decided(u16),
}

/// The verdict of the library about the body of an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    /// The body is the document the provider asked for.
    Document,
    /// The body is not the document.
    Refusal,
    /// The body is the document of the publisher and its shape changed.
    Malformed,
}

/// The media types a text document is served with.
const TEXT_MEDIA_TYPES: &[&str] = &["text/plain", "text/csv", "application/octet-stream"];

/// Decides what the status of an answer means.
///
/// The status of the document is 200. A status of the upstream is a status the
/// upstream decides itself, and it is never repeated. Every other status of the
/// 2xx is a refusal.
pub fn status_of(status: u16) -> Status {
    match status {
        200 => Status::Document,
        201..=299 => Status::Refusal,
        status => Status::Decided(status),
    }
}

/// Decides what the body of an answer is.
///
/// The content type is the media type of the answer and the body the body of
/// the answer.
///
/// A JSON document is recognised by its body, because the body decides
/// whether the parser of the provider can read it. A text document is
/// recognised by its media type, because the runtime cannot tell a list of
/// addresses from any other text.
pub fn body_of(kind: DocumentKind, content_type: Option<&str>, body: &str) -> Body {
    match kind {
        DocumentKind::Json => {
            if is_json(body) {
                return Body::Document;
            }

            match media_type(content_type).as_deref() {
                Some("application/json") => Body::Malformed,
                _ => Body::Refusal,
            }
        }
        DocumentKind::Text => match media_type(content_type).as_deref() {
            None => Body::Document,
            Some(media) if TEXT_MEDIA_TYPES.contains(&media) => Body::Document,
            Some(_) => Body::Refusal,
        },
    }
}

/// Whether a body holds JSON.
///
/// A document of JSON holds one value or a sequence of values, one after the
/// other, which is what a list of JSON lines is.
fn is_json(body: &str) -> bool {
    let values = serde_json::Deserializer::from_str(body).into_iter::<serde::de::IgnoredAny>();
    let mut found = false;

    for value in values {
        if value.is_err() {
            return false;
        }
        found = true;
    }

    found
}

/// The media type of an answer, without its parameters.
fn media_type(content_type: Option<&str>) -> Option<String> {
    content_type.map(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    })
}

/// The excerpt of a body in the diagnosis of a refused request.
///
/// The excerpt holds at most [`EXCERPT_LIMIT`] bytes of the body, the control
/// characters are replaced, and a body that is longer is marked.
pub fn excerpt(body: &str) -> String {
    let cut = body.len() > EXCERPT_LIMIT;
    let bytes = &body.as_bytes()[..body.len().min(EXCERPT_LIMIT)];
    let printable: String = String::from_utf8_lossy(bytes)
        .chars()
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect();

    if cut {
        format!("{printable}...")
    } else {
        printable
    }
}

/// The host a URL names.
fn host_of(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(url) => url
            .host_str()
            .map(str::to_string)
            .unwrap_or_else(|| url.to_string()),
        Err(_) => url.to_string(),
    }
}

/// A URL without its query and its fragment.
///
/// The diagnosis of a refused request is written to a log, and a credential of
/// the host may live in the query of the URL.
fn url_without_credentials(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut url) => {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => url.to_string(),
    }
}

/// Whether an error is a failure of the route rather than an answer of the
/// upstream.
fn is_transport_failure(error: &ProviderError) -> bool {
    matches!(error, ProviderError::Transport(_) | ProviderError::Timeout)
}

/// Whether an error is the answer of the upstream rather than a failure of the
/// route.
fn is_answer_of_the_upstream(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Unauthorized
            | ProviderError::RateLimited { .. }
            | ProviderError::Status { .. }
    )
}

/// The address family of the peer of an answer.
fn peer_family(peer: Option<SocketAddr>) -> Option<AddressFamily> {
    peer.map(|peer| AddressFamily::of(peer.ip()))
}

/// The runtime a lookup provider performs its request in.
pub struct ProviderRuntime {
    clients: ClientSet,
    provider: OnceLock<ProviderId>,
    cooldown: Cooldown,
    quota: Arc<dyn Quota>,
    timeout: Duration,
    clock: Arc<dyn Clock>,
    families: Mutex<HashMap<String, AddressFamily>>,
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
        clients: ClientSet,
        quota: Arc<dyn Quota>,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            clients,
            provider: OnceLock::new(),
            cooldown: Cooldown::new(),
            quota,
            timeout,
            clock,
            families: Mutex::new(HashMap::new()),
        }
    }

    /// Names the provider the runtime serves.
    ///
    /// The name appears in the diagnosis of a refused document.
    pub fn set_provider(&self, provider: ProviderId) {
        if self.provider.set(provider).is_err() {
            tracing::warn!("the provider of the runtime was named twice");
        }
    }

    /// The provider the runtime serves.
    pub fn provider(&self) -> Option<&ProviderId> {
        self.provider.get()
    }

    /// The budget of the provider.
    pub fn quota(&self) -> &dyn Quota {
        self.quota.as_ref()
    }

    /// The HTTP client of the provider.
    pub fn client(&self) -> &reqwest::Client {
        self.clients.normal()
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

    /// Asks the upstream for the document of a credentialed request.
    ///
    /// The request is built by a closure that receives the client, because a
    /// refused request is repeated over the other address family and the
    /// request has to be built a second time.
    ///
    /// The answer is the document of the publisher when it carries the status
    /// 200 and the body the provider asked for. An answer that does not is
    /// repeated once over the other address family, and the diagnosis of the
    /// refusal is written to the log. A refusal that the repetition does not
    /// repair is reported with the coarse error of the provider.
    pub async fn send_document<F>(
        &self,
        url: &str,
        build: F,
        now: OffsetDateTime,
        kind: DocumentKind,
    ) -> Result<String, ProviderError>
    where
        F: Fn(&reqwest::Client) -> reqwest::RequestBuilder + Send + Sync,
    {
        self.fetch(url, build, now, kind, true).await
    }

    /// Asks the upstream for the document of a request that carries no
    /// credential.
    ///
    /// The answer is handled like the answer of [`ProviderRuntime::send_document`].
    pub async fn send_anonymous_document<F>(
        &self,
        url: &str,
        build: F,
        now: OffsetDateTime,
        kind: DocumentKind,
    ) -> Result<String, ProviderError>
    where
        F: Fn(&reqwest::Client) -> reqwest::RequestBuilder + Send + Sync,
    {
        self.fetch(url, build, now, kind, false).await
    }

    /// Fetches the document of a provider.
    async fn fetch<F>(
        &self,
        url: &str,
        build: F,
        now: OffsetDateTime,
        kind: DocumentKind,
        credentialed: bool,
    ) -> Result<String, ProviderError>
    where
        F: Fn(&reqwest::Client) -> reqwest::RequestBuilder + Send + Sync,
    {
        self.admit(now)?;

        let deadline = tokio::time::Instant::now() + self.timeout;

        let host = host_of(url);
        let remembered = self.family_of(&host);
        let client = match remembered {
            Some(family) => self.clients.pinned(family),
            None => self.clients.normal(),
        };

        let refusal = match self
            .attempt(client, &build, kind, credentialed, deadline)
            .await
        {
            Attempt::Document(body) => return Ok(body),
            Attempt::Failed(error) => {
                // A route that does not reach the host any more is not trusted
                // with the next request to that host.
                if remembered.is_some() && is_transport_failure(&error) {
                    self.forget(&host);
                }
                return Err(error);
            }
            Attempt::Refusal(refusal) => refusal,
        };

        self.diagnose(url, &refusal);

        // The refusal is repeated over the other address family: the family of
        // the peer that answered, or the family that was remembered for the
        // host when the peer is not known. A host that is known to neither is
        // reached over IPv4, the family that is available most often.
        let recovery = match peer_family(refusal.peer) {
            Some(family) => family.other(),
            None => remembered
                .map(AddressFamily::other)
                .unwrap_or(AddressFamily::Ipv4),
        };

        match self
            .attempt(
                self.clients.pinned(recovery),
                &build,
                kind,
                credentialed,
                deadline,
            )
            .await
        {
            Attempt::Document(body) => {
                self.remember(&host, recovery);
                Ok(body)
            }
            // The answer of the upstream is more informative than the refusal:
            // the provider cools down or it rejects the credentials.
            Attempt::Failed(error) if is_answer_of_the_upstream(&error) => Err(error),
            // A route that does not reach the host is not an answer of the
            // upstream, so the refusal stays the error of the lookup.
            Attempt::Failed(_) => Err(refusal.error()),
            Attempt::Refusal(refusal) => {
                self.diagnose(url, &refusal);
                Err(refusal.error())
            }
        }
    }

    /// Sends the request of an attempt and classifies the answer.
    async fn attempt<F>(
        &self,
        client: &reqwest::Client,
        build: &F,
        kind: DocumentKind,
        credentialed: bool,
        deadline: tokio::time::Instant,
    ) -> Attempt
    where
        F: Fn(&reqwest::Client) -> reqwest::RequestBuilder + Send + Sync,
    {
        let request = build(client);
        let response = match tokio::time::timeout_at(deadline, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Attempt::Failed(map_transport_error(&error)),
            Err(_) => return Attempt::Failed(ProviderError::Timeout),
        };

        let status = response.status();
        let refused = match status_of(status.as_u16()) {
            Status::Document => false,
            Status::Refusal => true,
            Status::Decided(_) => {
                return Attempt::Failed(self.status_error(status, credentialed, &response));
            }
        };

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let peer = response.remote_addr();

        let body = match tokio::time::timeout_at(deadline, response.text()).await {
            Ok(Ok(body)) => body,
            Ok(Err(error)) => return Attempt::Failed(map_transport_error(&error)),
            Err(_) => return Attempt::Failed(ProviderError::Timeout),
        };

        if refused {
            return Attempt::Refusal(Refusal {
                status: status.as_u16(),
                content_type,
                peer,
                body,
            });
        }

        match body_of(kind, content_type.as_deref(), &body) {
            Body::Document => Attempt::Document(body),
            Body::Refusal => Attempt::Refusal(Refusal {
                status: status.as_u16(),
                content_type,
                peer,
                body,
            }),
            Body::Malformed => Attempt::Failed(ProviderError::Parse(
                "the document is not a JSON document".to_string(),
            )),
        }
    }

    /// The error of a status the upstream decides itself.
    ///
    /// The status is never repeated, because it is the answer of the publisher
    /// about the request and not a document that did not arrive.
    fn status_error(
        &self,
        status: reqwest::StatusCode,
        credentialed: bool,
        response: &reqwest::Response,
    ) -> ProviderError {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return ProviderError::Unauthorized;
        }

        if credentialed && status == reqwest::StatusCode::FORBIDDEN {
            return ProviderError::Unauthorized;
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
            return ProviderError::RateLimited { retry_after };
        }

        ProviderError::Status {
            code: status.as_u16(),
        }
    }

    /// Writes the diagnosis of a refused request to the log.
    ///
    /// The diagnosis names the provider, the URL, the status, the content type
    /// and an excerpt of the body. It stays in the log, so the caller of the
    /// library reads the coarse error and the operator reads the diagnosis.
    fn diagnose(&self, url: &str, refusal: &Refusal) {
        let provider = self
            .provider
            .get()
            .map(|provider| provider.as_str())
            .unwrap_or("unknown");

        tracing::warn!(
            provider = %provider,
            url = %url_without_credentials(url),
            status = refusal.status,
            content_type = %refusal.content_type.as_deref().unwrap_or("none"),
            body = %excerpt(&refusal.body),
            "the upstream did not deliver the document"
        );
    }

    /// The family that delivered the document of a host.
    fn family_of(&self, host: &str) -> Option<AddressFamily> {
        crate::lock(&self.families).get(host).copied()
    }

    /// Remembers the family that delivered the document of a host.
    fn remember(&self, host: &str, family: AddressFamily) {
        crate::lock(&self.families).insert(host.to_string(), family);
    }

    /// Forgets the family that delivered the document of a host.
    fn forget(&self, host: &str) {
        crate::lock(&self.families).remove(host);
    }

    /// Checks the cooldown and the budget of the provider.
    fn admit(&self, now: OffsetDateTime) -> Result<(), ProviderError> {
        if let Some(remaining) = self.cooldown.remaining() {
            return Err(ProviderError::RateLimited {
                retry_after: Some(remaining),
            });
        }

        if !self.quota.try_consume(now) {
            return Err(ProviderError::QuotaExhausted);
        }

        Ok(())
    }

    async fn dispatch(
        &self,
        request: reqwest::RequestBuilder,
        now: OffsetDateTime,
        credentialed: bool,
    ) -> Result<reqwest::Response, ProviderError> {
        self.admit(now)?;

        let response = tokio::time::timeout(self.timeout, request.send())
            .await
            .map_err(|_| ProviderError::Timeout)?
            .map_err(|error| map_transport_error(&error))?;

        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        Err(self.status_error(status, credentialed, &response))
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

/// The outcome of one attempt of a request.
enum Attempt {
    /// The answer is the document of the publisher.
    Document(String),
    /// The answer is not the document of the publisher.
    Refusal(Refusal),
    /// The answer is an error the caller of the library reads.
    Failed(ProviderError),
}

/// The detail of a refused answer.
struct Refusal {
    /// The status of the answer.
    status: u16,
    /// The content type of the answer.
    content_type: Option<String>,
    /// The address of the peer of the answer.
    peer: Option<SocketAddr>,
    /// The body of the answer.
    body: String,
}

impl Refusal {
    /// The coarse error the caller of the library reads.
    fn error(&self) -> ProviderError {
        match self.status {
            200 => {
                ProviderError::Parse("the answer is not the document of the provider".to_string())
            }
            status => ProviderError::Status { code: status },
        }
    }
}

/// Parses a JSON body.
pub fn parse_body<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, ProviderError> {
    serde_json::from_str(body).map_err(|error| ProviderError::Parse(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use time::macros::datetime;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::{
        Body, DocumentKind, EXCERPT_LIMIT, ProviderRuntime, Status, body_of, excerpt, peer_family,
        status_of,
    };
    use crate::error::ProviderError;
    use crate::http::{AddressFamily, ClientSet};
    use crate::quota::daily_guard;

    fn now() -> time::OffsetDateTime {
        datetime!(2026-11-16 12:00:00 UTC)
    }

    /// The clients the runtime uses, each of them naming itself in a header.
    fn clients() -> ClientSet {
        ClientSet::new(client("normal"), client("ipv4"), client("ipv6"))
    }

    fn client(name: &str) -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-client",
            reqwest::header::HeaderValue::from_str(name).expect("the name is a header value"),
        );

        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .default_headers(headers)
            .build()
            .expect("the client is built")
    }

    fn runtime() -> ProviderRuntime {
        ProviderRuntime::new(
            clients(),
            daily_guard(100),
            Duration::from_secs(5),
            crate::clock::system_clock(),
        )
    }

    /// The client that carried a request.
    fn client_of(request: &Request) -> String {
        request
            .headers
            .get("x-client")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("normal")
            .to_string()
    }

    #[test]
    fn the_detection_covers_the_statuses_and_the_content_types() {
        // The kind of the document, the status, the content type, the body,
        // the verdict of the status and the verdict of the body.
        let cases = [
            (
                DocumentKind::Json,
                200,
                Some("application/json"),
                "{}",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Json,
                200,
                Some("text/xml"),
                "{}",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Json,
                200,
                None,
                "{}",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Json,
                200,
                Some("application/json"),
                "<html>",
                Status::Document,
                Body::Malformed,
            ),
            (
                DocumentKind::Json,
                200,
                Some("text/xml"),
                "<html>",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Json,
                200,
                Some("text/html"),
                "<html>",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Json,
                200,
                None,
                "<html>",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Json,
                203,
                Some("application/json"),
                "{}",
                Status::Refusal,
                Body::Document,
            ),
            (
                DocumentKind::Json,
                401,
                Some("application/json"),
                "{}",
                Status::Decided(401),
                Body::Document,
            ),
            (
                DocumentKind::Json,
                403,
                Some("application/json"),
                "{}",
                Status::Decided(403),
                Body::Document,
            ),
            (
                DocumentKind::Json,
                404,
                Some("application/json"),
                "{}",
                Status::Decided(404),
                Body::Document,
            ),
            (
                DocumentKind::Json,
                429,
                Some("application/json"),
                "{}",
                Status::Decided(429),
                Body::Document,
            ),
            (
                DocumentKind::Json,
                500,
                Some("application/json"),
                "{}",
                Status::Decided(500),
                Body::Document,
            ),
            (
                DocumentKind::Text,
                200,
                Some("text/plain"),
                "45.32.1.1",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Text,
                200,
                Some("text/csv"),
                "45.32.1.1",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Text,
                200,
                Some("application/octet-stream"),
                "45.32.1.1",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Text,
                200,
                None,
                "45.32.1.1",
                Status::Document,
                Body::Document,
            ),
            (
                DocumentKind::Text,
                200,
                Some("text/html"),
                "<html>",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Text,
                200,
                Some("application/json"),
                "{}",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Text,
                200,
                Some("text/xml"),
                "<xml/>",
                Status::Document,
                Body::Refusal,
            ),
            (
                DocumentKind::Text,
                203,
                Some("text/plain"),
                "45.32.1.1",
                Status::Refusal,
                Body::Document,
            ),
            (
                DocumentKind::Text,
                401,
                Some("text/plain"),
                "45.32.1.1",
                Status::Decided(401),
                Body::Document,
            ),
            (
                DocumentKind::Text,
                403,
                Some("text/plain"),
                "45.32.1.1",
                Status::Decided(403),
                Body::Document,
            ),
            (
                DocumentKind::Text,
                404,
                Some("text/plain"),
                "45.32.1.1",
                Status::Decided(404),
                Body::Document,
            ),
            (
                DocumentKind::Text,
                429,
                Some("text/plain"),
                "45.32.1.1",
                Status::Decided(429),
                Body::Document,
            ),
            (
                DocumentKind::Text,
                500,
                Some("text/plain"),
                "45.32.1.1",
                Status::Decided(500),
                Body::Document,
            ),
        ];

        for (kind, status, content_type, body, expected_status, expected_body) in cases {
            assert_eq!(
                status_of(status),
                expected_status,
                "the status {status} of the answer"
            );
            assert_eq!(
                body_of(kind, content_type, body),
                expected_body,
                "the body of the answer of the status {status} with the content type {content_type:?}"
            );
        }
    }

    #[test]
    fn the_media_type_is_read_without_its_parameters() {
        assert_eq!(
            body_of(
                DocumentKind::Text,
                Some("text/plain; charset=utf-8"),
                "45.32.1.1"
            ),
            Body::Document
        );
    }

    #[test]
    fn a_document_of_json_lines_is_a_json_document() {
        assert_eq!(
            body_of(
                DocumentKind::Json,
                Some("application/json"),
                "{\"cidr\":\"192.0.2.0/24\"}\n{\"cidr\":\"198.51.100.0/24\"}\n"
            ),
            Body::Document
        );
    }

    #[tokio::test]
    async fn a_status_the_upstream_decides_is_not_repeated() {
        let cases = [
            (401, ProviderError::Unauthorized),
            (403, ProviderError::Status { code: 403 }),
            (404, ProviderError::Status { code: 404 }),
            (500, ProviderError::Status { code: 500 }),
        ];

        for (status, expected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            let runtime = runtime();
            let url = server.uri();
            let error = runtime
                .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
                .await
                .expect_err("the answer is refused");

            assert_eq!(error, expected);
            assert_eq!(
                server
                    .received_requests()
                    .await
                    .expect("the requests are recorded")
                    .len(),
                1,
                "the status {status} was not repeated"
            );
        }
    }

    #[tokio::test]
    async fn a_rate_limited_answer_is_not_repeated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "60"))
            .mount(&server)
            .await;

        let runtime = runtime();
        let url = server.uri();
        let error = runtime
            .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
            .await
            .expect_err("the answer is refused");

        assert_eq!(
            error,
            ProviderError::RateLimited {
                retry_after: Some(Duration::from_secs(60))
            }
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("the requests are recorded")
                .len(),
            1,
            "the rate limit was not repeated"
        );
    }

    #[tokio::test]
    async fn the_error_of_the_repetition_is_the_error_the_caller_reads() {
        let server = MockServer::start().await;
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        Mock::given(method("GET"))
            .respond_with(move |_: &wiremock::Request| {
                if served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(203)
                        .insert_header("content-type", "text/xml")
                        .set_body_bytes(b"no")
                } else {
                    ResponseTemplate::new(429).insert_header("Retry-After", "60")
                }
            })
            .mount(&server)
            .await;

        let runtime = runtime();
        let url = server.uri();
        let error = runtime
            .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
            .await
            .expect_err("the document is refused");

        assert_eq!(
            error,
            ProviderError::RateLimited {
                retry_after: Some(Duration::from_secs(60))
            },
            "the rate limit of the repetition reaches the caller"
        );
    }

    #[tokio::test]
    async fn a_route_that_does_not_reach_the_host_is_not_trusted_again() {
        let runtime = runtime();
        runtime.remember("127.0.0.1", AddressFamily::Ipv6);

        let url = "http://127.0.0.1:1/list";
        let error = runtime
            .send_anonymous_document(url, |client| client.get(url), now(), DocumentKind::Text)
            .await
            .expect_err("the host is not reachable");

        assert!(
            matches!(error, ProviderError::Transport(_)),
            "the route failed: {error}"
        );
        assert_eq!(
            runtime.family_of("127.0.0.1"),
            None,
            "the route is not trusted with the next request"
        );
    }

    #[tokio::test]
    async fn a_lookup_is_bounded_by_the_timeout_of_the_provider() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(203)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(b"no")
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&server)
            .await;

        let runtime = ProviderRuntime::new(
            clients(),
            daily_guard(100),
            Duration::from_millis(500),
            crate::clock::system_clock(),
        );
        let url = server.uri();
        let started = std::time::Instant::now();
        let _ = runtime
            .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
            .await;

        assert!(
            started.elapsed() < Duration::from_millis(650),
            "the lookup did not wait for the repetition: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_family_of_an_answer_is_read_from_the_address_of_its_peer() {
        assert_eq!(
            peer_family(Some("127.0.0.1:80".parse().unwrap())),
            Some(AddressFamily::Ipv4)
        );
        assert_eq!(
            peer_family(Some("[::1]:80".parse().unwrap())),
            Some(AddressFamily::Ipv6)
        );
        assert_eq!(peer_family(None), None);
    }

    #[tokio::test]
    async fn a_refusal_is_repeated_over_the_other_address_family() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(203)
                    .insert_header("content-type", "text/xml")
                    .set_body_bytes(b"no"),
            )
            .mount(&server)
            .await;

        let runtime = runtime();
        let url = server.uri();
        let error = runtime
            .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
            .await
            .expect_err("the document is refused");

        assert_eq!(error, ProviderError::Status { code: 203 });

        let requests = server
            .received_requests()
            .await
            .expect("the requests are recorded");
        assert_eq!(requests.len(), 2);
        assert_eq!(client_of(&requests[0]), "normal");
        assert_eq!(
            client_of(&requests[1]),
            "ipv6",
            "the request was repeated over the other address family"
        );
    }

    #[tokio::test]
    async fn a_document_that_is_delivered_is_not_repeated() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string("{}"),
            )
            .mount(&server)
            .await;

        let runtime = runtime();
        let url = server.uri();
        let body = runtime
            .send_anonymous_document(&url, |client| client.get(&url), now(), DocumentKind::Json)
            .await
            .expect("the document is delivered");

        assert_eq!(body, "{}");
        assert_eq!(
            server
                .received_requests()
                .await
                .expect("the requests are recorded")
                .len(),
            1
        );
    }

    #[test]
    fn an_excerpt_holds_at_most_64_bytes_of_the_body() {
        let body = "x".repeat(200);
        let excerpt = excerpt(&body);

        assert!(excerpt.len() <= EXCERPT_LIMIT + 3);
        assert!(
            excerpt.ends_with("..."),
            "a body that is cut is marked: {excerpt}"
        );
    }

    #[test]
    fn an_excerpt_replaces_the_control_characters() {
        let excerpt = excerpt("a\u{0}b\nc");

        assert!(!excerpt.contains('\u{0}'));
        assert!(!excerpt.contains('\n'));
        assert_eq!(excerpt, "a.b.c");
    }

    #[test]
    fn an_excerpt_of_a_short_body_is_the_body() {
        assert_eq!(excerpt("45.32.1.1"), "45.32.1.1");
    }

    #[test]
    fn the_budget_is_spent_once_per_lookup() {
        let runtime = runtime();

        assert!(runtime.quota().try_consume(now()));
        assert_eq!(runtime.quota().used(now()), 1);
    }

    #[test]
    fn the_runtime_names_the_provider_it_serves() {
        let runtime = runtime();

        assert!(runtime.provider().is_none());
        runtime.set_provider(crate::model::ProviderId::CINS);
        assert_eq!(
            runtime.provider().map(|provider| provider.as_str()),
            Some("cins")
        );
    }

    #[test]
    fn the_quota_of_the_runtime_is_the_one_it_was_built_with() {
        let runtime = Arc::new(runtime());

        assert_eq!(runtime.quota().bounded_limit(), Some(100));
    }
}
