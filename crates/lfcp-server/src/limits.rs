//! Abuse limits for a server open to unknown clients (POST-003; security
//! review H5, M2, M3): the client address behind a trusted proxy, and the
//! configured limits.
//!
//! Every limit here is server infrastructure, never LFCP Resource
//! authority. Refusals use the WIRE-01 §62 codes `RATE_LIMITED` and
//! `QUOTA_EXCEEDED` on the WebSocket, and HTTP 429 on HTTP.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// The abuse limits of [`crate::config::Config`]. For the per-IP and rate
/// limits, 0 disables the limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbuseLimits {
    /// Peers whose client-IP header is believed.
    pub trusted_proxies: Vec<Cidr>,
    /// The header carrying the client IP (lower case).
    pub client_ip_header: String,
    /// Open WebSocket connections per client IP.
    pub max_connections_per_ip: usize,
    /// New WebSocket connections per client IP per minute.
    pub connections_per_ip_per_minute: u32,
    /// LFCP messages per second on one WebSocket connection.
    pub ws_messages_per_second: u32,
    /// The burst of [`AbuseLimits::ws_messages_per_second`].
    pub ws_message_burst: u32,
    /// Admin HTTP requests (`/setup`, `/admin/*`) per client IP per minute.
    pub admin_requests_per_ip_per_minute: u32,
    /// The most client IPs tracked at once; idle ones are evicted first.
    pub max_tracked_ips: usize,
    /// Quota mode: Resources one Principal may host.
    pub quota_resources_per_principal: u64,
    /// Quota mode: stored bytes across one Principal's Resources.
    pub quota_bytes_per_principal: u64,
    /// Quota mode: stored bytes of one Resource.
    pub quota_bytes_per_resource: u64,
    /// Quota mode: new Resources hosted per client IP per 24 hours.
    pub hosts_per_ip_per_day: u32,
    /// Every mode: refuse new hosting and writes past this many stored
    /// bytes; `None` is no cap.
    pub max_total_bytes: Option<u64>,
    /// Every mode: refuse new hosting and writes when the free disk space
    /// of the state directory is under this; 0 disables the check.
    pub min_free_bytes: u64,
    /// How long a free disk space reading is reused, in milliseconds.
    pub disk_check_interval_ms: u64,
}

/// 1 MiB.
const MIB: u64 = 1024 * 1024;

impl Default for AbuseLimits {
    fn default() -> AbuseLimits {
        AbuseLimits {
            trusted_proxies: Vec::new(),
            client_ip_header: "x-forwarded-for".into(),
            max_connections_per_ip: 32,
            connections_per_ip_per_minute: 20,
            ws_messages_per_second: 50,
            ws_message_burst: 200,
            admin_requests_per_ip_per_minute: 60,
            max_tracked_ips: 65_536,
            quota_resources_per_principal: 20,
            quota_bytes_per_principal: 256 * MIB,
            quota_bytes_per_resource: 128 * MIB,
            hosts_per_ip_per_day: 10,
            max_total_bytes: None,
            min_free_bytes: 2048 * MIB,
            disk_check_interval_ms: 10_000,
        }
    }
}

impl AbuseLimits {
    /// The rules every field must meet: the field and what is wrong.
    pub fn validate(&self) -> Result<(), (&'static str, &'static str)> {
        if hyper::header::HeaderName::from_bytes(self.client_ip_header.as_bytes()).is_err() {
            return Err(("client_ip_header", "must be an HTTP header name"));
        }
        let rates = [
            ("max_connections_per_ip", self.max_connections_per_ip as u64),
            (
                "connections_per_ip_per_minute",
                u64::from(self.connections_per_ip_per_minute),
            ),
            (
                "ws_messages_per_second",
                u64::from(self.ws_messages_per_second),
            ),
            ("ws_message_burst", u64::from(self.ws_message_burst)),
            (
                "admin_requests_per_ip_per_minute",
                u64::from(self.admin_requests_per_ip_per_minute),
            ),
            ("hosts_per_ip_per_day", u64::from(self.hosts_per_ip_per_day)),
        ];
        for (field, value) in rates {
            if value > 1_000_000 {
                return Err((field, "must be between 0 and 1000000"));
            }
        }
        if self.ws_messages_per_second > 0 && self.ws_message_burst == 0 {
            return Err((
                "ws_message_burst",
                "must be at least 1 while ws_messages_per_second is set",
            ));
        }
        if !(1024..=10_000_000).contains(&self.max_tracked_ips) {
            return Err(("max_tracked_ips", "must be between 1024 and 10000000"));
        }
        for (field, value) in [
            (
                "quota_resources_per_principal",
                self.quota_resources_per_principal,
            ),
            ("quota_bytes_per_principal", self.quota_bytes_per_principal),
            ("quota_bytes_per_resource", self.quota_bytes_per_resource),
        ] {
            if value == 0 || value > i64::MAX as u64 {
                return Err((field, "must be between 1 and 2^63-1"));
            }
        }
        if self
            .max_total_bytes
            .is_some_and(|n| n == 0 || n > i64::MAX as u64)
        {
            return Err(("max_total_bytes", "must be between 1 and 2^63-1"));
        }
        if !(100..=3_600_000).contains(&self.disk_check_interval_ms) {
            return Err(("disk_check_interval_ms", "must be between 100 and 3600000"));
        }
        Ok(())
    }
}

/// An IP network: an address and a prefix length. Written `addr/len`, or
/// a bare address for a single host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Why a [`Cidr`] does not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CidrError(String);

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not an IP address or CIDR network", self.0)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(text: &str) -> Result<Cidr, CidrError> {
        let bad = || CidrError(text.to_owned());
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let network = canonical(addr.parse::<IpAddr>().map_err(|_| bad())?);
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(bad)?
            }
            Some(_) => return Err(bad()),
            None => max,
        };
        Ok(Cidr {
            network: mask(network, prefix),
            prefix,
        })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl Cidr {
    /// Whether `ip` is in this network (an IPv4-mapped IPv6 address counts
    /// as its IPv4 address).
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        ip.is_ipv4() == self.network.is_ipv4() && mask(ip, self.prefix) == self.network
    }
}

/// `ip` with an IPv4-mapped IPv6 address turned into IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// `ip` with every bit past `prefix` cleared.
fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6((bits & mask).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn cidrs_parse_and_match() {
        let net: Cidr = "172.18.0.0/16".parse().unwrap();
        assert!(net.contains(ip("172.18.3.4")));
        assert!(!net.contains(ip("172.19.0.1")));
        assert!(net.contains(ip("::ffff:172.18.0.9")), "IPv4-mapped");
        assert_eq!(
            "10.1.2.3/8".parse::<Cidr>().unwrap().to_string(),
            "10.0.0.0/8"
        );
        let host: Cidr = "10.0.0.7".parse().unwrap();
        assert!(host.contains(ip("10.0.0.7")) && !host.contains(ip("10.0.0.8")));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("8.8.8.8")) && !all.contains(ip("::1")));
        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        assert!("::/0".parse::<Cidr>().unwrap().contains(ip("2001:db8::1")));
        for bad in [
            "",
            "x",
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "::/129",
            "1.2.3/8",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn defaults_are_valid() {
        assert_eq!(AbuseLimits::default().validate(), Ok(()));
    }
}
