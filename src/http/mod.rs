//! HTTP client construction and error mapping.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::error::{ConfigError, ProviderError};

/// The user agent the library sends upstream.
pub fn user_agent() -> String {
    format!("badbots/{}", env!("CARGO_PKG_VERSION"))
}

/// The address family a client is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// The family that is not this one.
    pub fn other(self) -> AddressFamily {
        match self {
            AddressFamily::Ipv4 => AddressFamily::Ipv6,
            AddressFamily::Ipv6 => AddressFamily::Ipv4,
        }
    }

    /// The family an address belongs to.
    pub fn of(address: IpAddr) -> AddressFamily {
        match address {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }
}

/// The clients the library reaches the upstream with.
///
/// The set holds the client that is bound to no address family and the two
/// clients that are bound to one family each. A client that is bound to a
/// family reaches no other family, so the library can repeat a request over
/// the other family when an answer is not the document of the publisher.
#[derive(Clone, Debug)]
pub struct ClientSet {
    normal: reqwest::Client,
    ipv4: reqwest::Client,
    ipv6: reqwest::Client,
}

impl ClientSet {
    /// Creates a set from three clients.
    ///
    /// The client of a family reaches no other family when it is bound to the
    /// local address of that family.
    pub fn new(normal: reqwest::Client, ipv4: reqwest::Client, ipv6: reqwest::Client) -> Self {
        Self { normal, ipv4, ipv6 }
    }

    /// The client that is bound to no family.
    pub fn normal(&self) -> &reqwest::Client {
        &self.normal
    }

    /// The client that is bound to the family.
    pub fn pinned(&self, family: AddressFamily) -> &reqwest::Client {
        match family {
            AddressFamily::Ipv4 => &self.ipv4,
            AddressFamily::Ipv6 => &self.ipv6,
        }
    }
}

/// Builds the clients the library reaches the upstream with.
///
/// The clients use rustls, so the library builds without a system TLS stack.
/// The two clients that are bound to a family are the ordinary client with the
/// local address of that family, which keeps them from reaching the other one.
///
/// A root certificate is trusted in addition to the roots the client trusts by
/// default. A proxy replaces the proxy of the environment when one is named;
/// a proxy takes the place of the upstream on the path, so a client that is
/// bound to a family is bound to the family of the proxy.
pub fn build_clients(
    timeout: Duration,
    root_certificate: Option<&str>,
    proxy: Option<&str>,
) -> Result<ClientSet, ConfigError> {
    let normal = client(timeout, root_certificate, proxy, None)?;
    let ipv4 = client(
        timeout,
        root_certificate,
        proxy,
        Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    )?;
    let ipv6 = client(
        timeout,
        root_certificate,
        proxy,
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    )?;

    Ok(ClientSet::new(normal, ipv4, ipv6))
}

/// Builds one client of the set.
fn client(
    timeout: Duration,
    root_certificate: Option<&str>,
    proxy: Option<&str>,
    local_address: Option<IpAddr>,
) -> Result<reqwest::Client, ConfigError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(user_agent());

    if let Some(pem) = root_certificate {
        let certificates =
            reqwest::Certificate::from_pem_bundle(pem.as_bytes()).map_err(|error| {
                ConfigError::Invalid(format!("the root certificate could not be read: {error}"))
            })?;

        if certificates.is_empty() {
            return Err(ConfigError::Invalid(
                "the root certificate holds no certificate".to_string(),
            ));
        }

        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }

    if let Some(url) = proxy {
        let proxy = reqwest::Proxy::all(url).map_err(|error| {
            ConfigError::Invalid(format!("the proxy could not be read: {error}"))
        })?;
        builder = builder.proxy(proxy);
    }

    if let Some(address) = local_address {
        builder = builder.local_address(address);
    }

    builder
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{AddressFamily, build_clients};

    #[tokio::test]
    async fn a_client_of_a_family_reaches_no_other_family() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("the document"))
            .mount(&server)
            .await;

        let clients =
            build_clients(Duration::from_secs(5), None, None).expect("the clients are built");

        let response = clients
            .pinned(AddressFamily::Ipv4)
            .get(server.uri())
            .send()
            .await;
        assert!(
            response.is_ok(),
            "the client of the family of the server reaches it"
        );

        let response = clients
            .pinned(AddressFamily::Ipv6)
            .get(server.uri())
            .send()
            .await;
        assert!(
            response.is_err(),
            "the client of the other family does not reach it"
        );
    }

    #[test]
    fn a_root_certificate_that_cannot_be_read_is_rejected() {
        let error = build_clients(Duration::from_secs(5), Some("not a certificate"), None)
            .expect_err("the certificate is rejected");

        assert!(
            error.to_string().contains("root certificate"),
            "the error names the certificate: {error}"
        );
    }

    #[test]
    fn a_proxy_that_cannot_be_read_is_rejected() {
        let error = build_clients(Duration::from_secs(5), None, Some("not a proxy"))
            .expect_err("the proxy is rejected");

        assert!(
            error.to_string().contains("proxy"),
            "the error names the proxy: {error}"
        );
    }
}
