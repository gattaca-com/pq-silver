use std::net::{Ipv4Addr, SocketAddr};

use flux::timing::{Duration, Instant};
use flux_network::{
    NetworkCore,
    http::{HttpNetwork, HttpPool, RequestId},
};
use silver_common::Error;

pub const JSON: &str = "application/json";
pub const SSZ: &str = "application/octet-stream";
pub const JSON_HEADERS: [(&str, &str); 2] = [("Accept", JSON), ("Content-Type", JSON)];
const MAX_HEADERS: usize = 1 + 4;

/// A failed lookup retries at this pace.
const RESOLVE_RETRY_SECS: u64 = 2;
/// A node closes a keep-alive connection once it idles (silver's after 5 s),
/// and a request can go out on it before the close is seen. One resend
/// covers that; it costs flux a copy of the body.
const RESENDS: u8 = 1;

enum Connection {
    Resolving { retry_at: Option<Instant> },
    Pooled { pool: HttpPool, addr: SocketAddr },
}

/// An `http(s)://host[:port]` URL and its pooled connections.
pub struct HttpEndpoint {
    /// Names the endpoint in errors and logs.
    kind: &'static str,
    pub url: String,
    pub host: String,
    /// The URL's `host:port`, sent as `Host` rather than the resolved address.
    authority: String,
    port: u16,
    tls: bool,
    connection: Connection,
}

impl HttpEndpoint {
    /// No path prefix and no IPv6.
    pub fn parse(kind: &'static str, url: &str) -> Result<Self, Error> {
        let invalid = |why: &str| Error::ConfigError(format!("{kind} {url}: {why}"));
        let (tls, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
            (Some(rest), _) => (true, rest),
            (None, Some(rest)) => (false, rest),
            (None, None) => return Err(invalid("not an http:// or https:// URL")),
        };
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if !path.is_empty() {
            return Err(invalid("a path prefix is not supported"));
        }
        if authority.starts_with('[') {
            return Err(invalid("IPv6 addresses are not supported"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| invalid("bad port"))?),
            None => (authority, if tls { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(invalid("no host"));
        }
        Ok(Self {
            kind,
            url: url.to_owned(),
            host: host.to_owned(),
            authority: authority.to_owned(),
            port,
            tls,
            connection: Connection::Resolving { retry_at: None },
        })
    }

    pub fn wants_resolving(&mut self, now: Instant) -> bool {
        match &mut self.connection {
            Connection::Resolving { retry_at } if retry_at.is_none_or(|at| at <= now) => {
                *retry_at = Some(now + Duration::from_secs(RESOLVE_RETRY_SECS));
                true
            }
            _ => false,
        }
    }

    pub fn resolved(
        &mut self,
        http: &mut HttpNetwork,
        net: &mut NetworkCore,
        addrs: &[Ipv4Addr],
        connections: usize,
    ) {
        let Some(&ip) = addrs.first() else {
            silver_log::warn!(kind = self.kind, url = %self.url, "host did not resolve");
            return;
        };
        let addr = SocketAddr::from((ip, self.port));
        let pool = if self.tls {
            http.pool_tls(net, addr, &self.host, connections)
        } else {
            http.pool(net, addr, connections)
        };
        self.connection = Connection::Pooled { pool, addr };
    }

    pub fn is_pooled(&self) -> bool {
        matches!(self.connection, Connection::Pooled { .. })
    }

    pub fn addr(&self) -> Option<SocketAddr> {
        match self.connection {
            Connection::Pooled { addr, .. } => Some(addr),
            Connection::Resolving { .. } => None,
        }
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn tls_host(&self) -> Option<&str> {
        self.tls.then_some(self.host.as_str())
    }

    pub fn send(
        &self,
        http: &mut HttpNetwork,
        net: &mut NetworkCore,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Option<RequestId> {
        let Connection::Pooled { pool, .. } = self.connection else { return None };
        let mut all = [("Host", self.authority.as_str()); MAX_HEADERS];
        all[1..=headers.len()].copy_from_slice(headers);
        http.send(net, pool, method, path, &all[..=headers.len()], body, RESENDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(url: &str) -> (String, u16, bool, String) {
        let endpoint = HttpEndpoint::parse("beacon node", url).unwrap();
        (endpoint.host, endpoint.port, endpoint.tls, endpoint.authority)
    }

    #[test]
    fn urls_split_into_host_port_and_scheme() {
        assert_eq!(parsed("http://bn:5052"), ("bn".into(), 5052, false, "bn:5052".into()));
        assert_eq!(
            parsed("https://bn.example/"),
            ("bn.example".into(), 443, true, "bn.example".into())
        );
        assert_eq!(parsed("http://10.0.0.1"), ("10.0.0.1".into(), 80, false, "10.0.0.1".into()));
    }

    #[test]
    fn unsupported_urls_are_config_errors() {
        for url in ["http://bn:5052/prefix", "http://[::1]:5052", "http://bn:port", "http://:5052"]
        {
            let parsed = HttpEndpoint::parse("beacon node", url);
            assert!(matches!(parsed, Err(Error::ConfigError(_))), "{url}");
        }
    }
}
