//! Client address resolution and the failed-login log lines that fail2ban matches.
//!
//! The log format is a stable interface: `contrib/fail2ban/filter.d/lightbws.conf` depends on it.
//! Keep `ip=` as the first field and quote every client-supplied value.

use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderName};

/// Longest client-supplied identifier written to the log. Longer values are cut.
const MAX_LOGGED_IDENTIFIER: usize = 64;

/// Returns the address of the client that sent the request.
///
/// When `ip_header` is set (for example `X-Real-IP` behind a reverse proxy), its value wins. For a
/// comma-separated list such as `X-Forwarded-For`, the last entry is used: it is the one added by
/// the proxy closest to LightBWS, while earlier entries can be forged by the client. Without the
/// header, or when it does not hold an address, the TCP peer address is used.
pub fn resolve(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    ip_header: Option<&HeaderName>,
) -> Option<IpAddr> {
    ip_header
        .and_then(|name| headers.get(name))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(parse_address)
        .or_else(|| peer.map(|peer| peer.ip()))
        .map(|ip| ip.to_canonical())
}

fn parse_address(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|address| address.ip()))
}

/// Which login endpoint a failure came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginKind {
    /// The Web UI username and password login.
    Web,
    /// The SDK and `bws` access-token exchange at `/identity/connect/token`.
    Machine,
}

/// Why a login was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    InvalidCredentials,
    RateLimited,
}

impl FailureReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "invalid_credentials",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// Writes one warning for a refused login, for example:
///
/// ```text
/// 2026-10-25T11:30:00.123456Z  WARN lightbws::auth: web login failed ip=203.0.113.7 reason=invalid_credentials username="admin"
/// ```
pub fn log_login_failure(
    kind: LoginKind,
    ip: Option<IpAddr>,
    reason: FailureReason,
    identifier: &str,
) {
    let ip = ip.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    let identifier = truncate(identifier);
    let reason = reason.as_str();
    match kind {
        LoginKind::Web => tracing::warn!(
            target: "lightbws::auth",
            ip = %ip,
            reason = %reason,
            username = ?identifier,
            "web login failed"
        ),
        LoginKind::Machine => tracing::warn!(
            target: "lightbws::auth",
            ip = %ip,
            reason = %reason,
            client_id = ?identifier,
            "machine login failed"
        ),
    }
}

fn truncate(value: &str) -> &str {
    match value.char_indices().nth(MAX_LOGGED_IDENTIFIER) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    use super::{resolve, truncate};

    fn peer() -> Option<SocketAddr> {
        Some("192.0.2.10:51000".parse().unwrap())
    }

    fn headers(name: &'static str, value: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static(value));
        headers
    }

    #[test]
    fn uses_the_peer_without_a_configured_header() {
        let forged = headers("x-real-ip", "198.51.100.1");
        assert_eq!(
            resolve(&forged, peer(), None),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(resolve(&HeaderMap::new(), None, None), None);
    }

    #[test]
    fn reads_the_configured_header() {
        let name = HeaderName::from_static("x-real-ip");
        assert_eq!(
            resolve(&headers("x-real-ip", " 198.51.100.1 "), peer(), Some(&name)),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        );
        assert_eq!(
            resolve(
                &headers("x-real-ip", "[2001:db8::1]:443"),
                peer(),
                Some(&name)
            ),
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
    }

    #[test]
    fn trusts_only_the_last_forwarded_entry() {
        let name = HeaderName::from_static("x-forwarded-for");
        let value = headers("x-forwarded-for", "203.0.113.99, 198.51.100.1");
        assert_eq!(
            resolve(&value, peer(), Some(&name)),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)))
        );
    }

    #[test]
    fn falls_back_to_the_peer_for_a_missing_or_invalid_header() {
        let name = HeaderName::from_static("x-real-ip");
        let expected = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(resolve(&HeaderMap::new(), peer(), Some(&name)), expected);
        assert_eq!(
            resolve(&headers("x-real-ip", "not-an-ip"), peer(), Some(&name)),
            expected
        );
    }

    #[test]
    fn unwraps_ipv4_mapped_addresses() {
        let peer = Some("[::ffff:192.0.2.10]:51000".parse().unwrap());
        assert_eq!(
            resolve(&HeaderMap::new(), peer, None),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }

    #[test]
    fn truncates_long_identifiers_on_a_character_boundary() {
        assert_eq!(truncate("admin"), "admin");
        let long = "é".repeat(100);
        assert_eq!(truncate(&long).chars().count(), 64);
    }
}
