//! Abuse limits for a server open to unknown clients (POST-003; security
//! review H5, M2, M3): the client address behind a trusted proxy, and the
//! configured limits.
//!
//! **Client IP.** Behind a reverse proxy every TCP peer is the proxy, so
//! [`Proxies::client_ip`] believes the configured header
//! ([`AbuseLimits::client_ip_header`], default `X-Forwarded-For`) only
//! when the TCP peer is in [`AbuseLimits::trusted_proxies`]; otherwise the
//! peer address is the client. The header is read as a comma-separated
//! list (every line of it, in order) from the right: the rightmost entry
//! that is not itself a trusted proxy is the client, because entries left
//! of it were written by parties the server does not trust. If every
//! entry is trusted, the leftmost is the client. An entry that is not an
//! IP address stops the walk and the peer address is used.
//!
//! **Per-IP state** ([`IpTable`]) is keyed by the client IP, IPv6 by its
//! /64 prefix (one site gets a whole /64, so a single host could otherwise
//! spray addresses). It holds at most [`AbuseLimits::max_tracked_ips`]
//! entries: when full, entries with no open connection and nothing to
//! remember are dropped, then the least recently seen entries without an
//! open connection, down to 7/8 of the cap. An entry with an open
//! connection is never dropped, so the table is bounded by the cap plus
//! the server's connection cap.
//!
//! Every limit here is server infrastructure, never LFCP Resource
//! authority. Refusals use the WIRE-01 §62 codes `RATE_LIMITED` and
//! `QUOTA_EXCEEDED` on the WebSocket, and HTTP 429 on HTTP.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::header::HeaderMap;

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

/// A token bucket's rate: `per_second` tokens refill it, up to `burst`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rate {
    per_second: f64,
    burst: f64,
}

impl Rate {
    /// `count` per `period`, with a burst of `burst`; `None` when `count`
    /// is 0 (no limit).
    pub fn new(count: u32, period: Duration, burst: u32) -> Option<Rate> {
        (count > 0).then(|| Rate {
            per_second: f64::from(count) / period.as_secs_f64(),
            burst: f64::from(burst.max(1)),
        })
    }

    /// `count` per minute, with a burst of `count`.
    pub fn per_minute(count: u32) -> Option<Rate> {
        Rate::new(count, Duration::from_secs(60), count)
    }
}

/// A token bucket: one token per event, refilled at its [`Rate`].
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    rate: Rate,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    /// A full bucket at `now`.
    pub fn new(rate: Rate, now: Instant) -> Bucket {
        Bucket {
            rate,
            tokens: rate.burst,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate.per_second).min(self.rate.burst);
        self.at = now;
    }

    /// Take a token at `now`, or say how long until one is available.
    pub fn take(&mut self, now: Instant) -> Result<(), Duration> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - self.tokens) / self.rate.per_second,
            ))
        }
    }

    /// Whether the bucket would be full at `now`: it remembers nothing.
    fn is_full(&self, now: Instant) -> bool {
        let mut probe = *self;
        probe.refill(now);
        probe.tokens >= probe.rate.burst
    }
}

/// Whole seconds to wait, at least 1: an HTTP `Retry-After` value.
pub fn retry_after(wait: Duration) -> u64 {
    wait.as_secs_f64().ceil().max(1.0) as u64
}

/// Where the client IP of a request comes from.
#[derive(Clone, Debug)]
pub struct Proxies {
    trusted: Vec<Cidr>,
    header: String,
}

impl Proxies {
    /// The proxies and header of `limits`.
    pub fn new(limits: &AbuseLimits) -> Proxies {
        Proxies {
            trusted: limits.trusted_proxies.clone(),
            header: limits.client_ip_header.clone(),
        }
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(ip))
    }

    /// The client IP of a request from TCP peer `peer` (see the module
    /// documentation).
    pub fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical(peer);
        if !self.trusts(peer) {
            return peer;
        }
        let mut entries = Vec::new();
        for value in headers.get_all(self.header.as_str()) {
            let Ok(value) = value.to_str() else {
                return peer;
            };
            entries.extend(value.split(',').map(str::trim));
        }
        let mut client = None;
        for entry in entries.iter().rev() {
            let Some(ip) = parse_entry(entry) else {
                return peer;
            };
            client = Some(ip);
            if !self.trusts(ip) {
                break;
            }
        }
        client.unwrap_or(peer)
    }
}

/// One client-IP header entry: an address, possibly with a port
/// (`1.2.3.4:5678`, `[2001:db8::1]:443`).
fn parse_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    entry
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|s| canonical(s.ip()))
}

/// The per-IP key: the address, an IPv6 one cut to its /64 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpKey(IpAddr);

impl IpKey {
    /// The key of `ip`.
    pub fn of(ip: IpAddr) -> IpKey {
        match canonical(ip) {
            v4 @ IpAddr::V4(_) => IpKey(v4),
            v6 => IpKey(mask(v6, 64)),
        }
    }
}

/// Why [`IpTable::connect`] refused a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// [`AbuseLimits::max_connections_per_ip`] connections are open.
    TooMany,
    /// [`AbuseLimits::connections_per_ip_per_minute`] were opened; one is
    /// allowed again after this long.
    Rate(Duration),
}

#[derive(Debug)]
struct Entry {
    open: usize,
    seen: Instant,
    connects: Option<Bucket>,
    admin: Option<Bucket>,
}

impl Entry {
    fn new(now: Instant) -> Entry {
        Entry {
            open: 0,
            seen: now,
            connects: None,
            admin: None,
        }
    }

    /// Nothing to remember: dropping it changes no decision.
    fn is_idle(&self, now: Instant) -> bool {
        self.open == 0
            && self.connects.is_none_or(|b| b.is_full(now))
            && self.admin.is_none_or(|b| b.is_full(now))
    }
}

/// Take a token from the bucket in `slot` (created full at `rate`).
fn take(slot: &mut Option<Bucket>, rate: Option<Rate>, now: Instant) -> Result<(), Duration> {
    match rate {
        Some(rate) => slot.get_or_insert_with(|| Bucket::new(rate, now)).take(now),
        None => Ok(()),
    }
}

/// Per-client-IP state (see the module documentation).
#[derive(Debug)]
pub struct IpTable {
    max_open: usize,
    connects: Option<Rate>,
    admin: Option<Rate>,
    max_tracked: usize,
    entries: Mutex<HashMap<IpKey, Entry>>,
}

impl IpTable {
    /// A table enforcing `limits`.
    pub fn new(limits: &AbuseLimits) -> Arc<IpTable> {
        Arc::new(IpTable {
            max_open: limits.max_connections_per_ip,
            connects: Rate::per_minute(limits.connections_per_ip_per_minute),
            admin: Rate::per_minute(limits.admin_requests_per_ip_per_minute),
            max_tracked: limits.max_tracked_ips,
            entries: Mutex::default(),
        })
    }

    /// How many IPs are tracked.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("never poisoned").len()
    }

    /// Whether no IP is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run `f` on the entry of `ip`, created (with eviction) if new.
    fn with<R>(&self, ip: IpAddr, now: Instant, f: impl FnOnce(&mut Entry) -> R) -> R {
        let key = IpKey::of(ip);
        let mut entries = self.entries.lock().expect("never poisoned");
        if !entries.contains_key(&key) && entries.len() >= self.max_tracked {
            evict(&mut entries, self.max_tracked, now);
        }
        let entry = entries.entry(key).or_insert_with(|| Entry::new(now));
        entry.seen = now;
        f(entry)
    }

    /// Open a WebSocket connection for `ip`: refused past
    /// [`AbuseLimits::max_connections_per_ip`] open ones, or
    /// [`AbuseLimits::connections_per_ip_per_minute`] new ones. The permit
    /// holds the place until dropped.
    pub fn connect(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Result<IpPermit, Refused> {
        let (max_open, connects) = (self.max_open, self.connects);
        self.with(ip, now, |entry| {
            if max_open > 0 && entry.open >= max_open {
                return Err(Refused::TooMany);
            }
            take(&mut entry.connects, connects, now).map_err(Refused::Rate)?;
            entry.open += 1;
            Ok(())
        })?;
        Ok(IpPermit {
            table: self.clone(),
            key: IpKey::of(ip),
        })
    }
}

impl IpTable {
    /// Admit one admin HTTP request from `ip`, or say how long until
    /// [`AbuseLimits::admin_requests_per_ip_per_minute`] admits one.
    pub fn admin_request(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let rate = self.admin;
        self.with(ip, now, |entry| take(&mut entry.admin, rate, now))
    }
}

/// Drop idle entries, then the least recently seen entries without an
/// open connection, until at most 7/8 of `cap` remain.
fn evict(entries: &mut HashMap<IpKey, Entry>, cap: usize, now: Instant) {
    let target = cap - cap / 8;
    entries.retain(|_, entry| !entry.is_idle(now));
    if entries.len() <= target {
        return;
    }
    let mut closed: Vec<(Instant, IpKey)> = entries
        .iter()
        .filter(|(_, entry)| entry.open == 0)
        .map(|(key, entry)| (entry.seen, *key))
        .collect();
    let excess = (entries.len() - target).min(closed.len());
    if excess == 0 {
        return;
    }
    closed.select_nth_unstable_by_key(excess - 1, |(seen, _)| *seen);
    for (_, key) in &closed[..excess] {
        entries.remove(key);
    }
}

/// A place under [`AbuseLimits::max_connections_per_ip`], released on drop.
#[derive(Debug)]
pub struct IpPermit {
    table: Arc<IpTable>,
    key: IpKey,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut entries = self.table.entries.lock().expect("never poisoned");
        if let Some(entry) = entries.get_mut(&self.key) {
            entry.open = entry.open.saturating_sub(1);
        }
    }
}

/// A connection's client: its IP and the per-IP table it is counted in.
#[derive(Clone, Debug)]
pub struct Client {
    ip: IpAddr,
    table: Arc<IpTable>,
}

impl Client {
    /// The client `ip`, tracked in `table`.
    pub fn new(ip: IpAddr, table: Arc<IpTable>) -> Client {
        Client {
            ip: canonical(ip),
            table,
        }
    }

    /// The client `ip` with a table of its own under default limits (for
    /// tests and tools).
    pub fn detached(ip: IpAddr) -> Client {
        Client::new(ip, IpTable::new(&AbuseLimits::default()))
    }

    /// The client IP.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The per-IP table the client is counted in.
    pub fn table(&self) -> &Arc<IpTable> {
        &self.table
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

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    fn proxies(trusted: &[&str], header: &str) -> Proxies {
        Proxies::new(&AbuseLimits {
            trusted_proxies: trusted.iter().map(|t| t.parse().unwrap()).collect(),
            client_ip_header: header.into(),
            ..AbuseLimits::default()
        })
    }

    #[test]
    fn the_header_is_believed_only_from_a_trusted_peer() {
        let xff = proxies(&["172.18.0.0/16"], "x-forwarded-for");
        let forged = headers(&[("x-forwarded-for", "203.0.113.9")]);
        // An untrusted peer: the header is ignored.
        assert_eq!(
            xff.client_ip(ip("198.51.100.1"), &forged),
            ip("198.51.100.1")
        );
        assert_eq!(
            proxies(&[], "x-forwarded-for").client_ip(ip("172.18.0.2"), &forged),
            ip("172.18.0.2"),
            "nothing is trusted by default"
        );
        // The proxy: the client it reports.
        assert_eq!(xff.client_ip(ip("172.18.0.2"), &forged), ip("203.0.113.9"));
        // No header from the proxy: the proxy itself.
        assert_eq!(
            xff.client_ip(ip("172.18.0.2"), &headers(&[])),
            ip("172.18.0.2")
        );
    }

    #[test]
    fn the_rightmost_untrusted_entry_is_the_client() {
        let xff = proxies(&["172.18.0.0/16", "10.0.0.0/8"], "x-forwarded-for");
        let peer = ip("172.18.0.2");
        // The client prepended a forged entry; the proxy appended the real one.
        let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.9")]);
        assert_eq!(xff.client_ip(peer, &h), ip("203.0.113.9"));
        // Trusted hops on the right are skipped, lines are joined in order.
        let h = headers(&[
            ("x-forwarded-for", "1.1.1.1, 203.0.113.9"),
            ("x-forwarded-for", "10.1.1.1"),
        ]);
        assert_eq!(xff.client_ip(peer, &h), ip("203.0.113.9"));
        // All trusted: the leftmost.
        let h = headers(&[("x-forwarded-for", "10.0.0.5, 10.0.0.6")]);
        assert_eq!(xff.client_ip(peer, &h), ip("10.0.0.5"));
        // Ports and brackets are accepted; garbage falls back to the peer.
        let h = headers(&[("x-forwarded-for", "[2001:db8::1]:443")]);
        assert_eq!(xff.client_ip(peer, &h), ip("2001:db8::1"));
        let h = headers(&[("x-forwarded-for", "203.0.113.9:5000")]);
        assert_eq!(xff.client_ip(peer, &h), ip("203.0.113.9"));
        let h = headers(&[("x-forwarded-for", "unknown, 203.0.113.9, junk")]);
        assert_eq!(xff.client_ip(peer, &h), peer);
        // Another header can be configured; X-Forwarded-For is then ignored.
        let cf = proxies(&["172.18.0.0/16"], "cf-connecting-ip");
        let h = headers(&[
            ("cf-connecting-ip", "198.51.100.7"),
            ("x-forwarded-for", "1.1.1.1"),
        ]);
        assert_eq!(cf.client_ip(peer, &h), ip("198.51.100.7"));
        let real = proxies(&["172.18.0.0/16"], "x-real-ip");
        let h = headers(&[("x-real-ip", "198.51.100.8")]);
        assert_eq!(real.client_ip(peer, &h), ip("198.51.100.8"));
        // An IPv4-mapped peer is matched as IPv4.
        assert_eq!(xff.client_ip(ip("::ffff:172.18.0.2"), &h), ip("172.18.0.2"));
    }

    #[test]
    fn ipv6_clients_are_grouped_by_their_64_prefix() {
        assert_eq!(
            IpKey::of(ip("2001:db8:1:2:aaaa::1")),
            IpKey::of(ip("2001:db8:1:2:bbbb::2"))
        );
        assert_ne!(
            IpKey::of(ip("2001:db8:1:2::1")),
            IpKey::of(ip("2001:db8:1:3::1"))
        );
        assert_ne!(IpKey::of(ip("192.0.2.1")), IpKey::of(ip("192.0.2.2")));
    }

    fn table(limits: AbuseLimits) -> Arc<IpTable> {
        IpTable::new(&limits)
    }

    #[test]
    fn buckets_refill_at_their_rate() {
        let now = Instant::now();
        let mut bucket = Bucket::new(Rate::new(2, Duration::from_secs(1), 3).unwrap(), now);
        for _ in 0..3 {
            assert_eq!(bucket.take(now), Ok(()));
        }
        assert_eq!(bucket.take(now), Err(Duration::from_millis(500)));
        let later = now + Duration::from_millis(500);
        assert_eq!(bucket.take(later), Ok(()));
        assert!(bucket.take(later).is_err());
        assert!(!bucket.is_full(later));
        assert!(bucket.is_full(later + Duration::from_secs(2)));
        assert_eq!(Rate::per_minute(0), None);
        assert_eq!(retry_after(Duration::from_millis(1)), 1);
        assert_eq!(retry_after(Duration::from_millis(19_990)), 20);
    }

    #[test]
    fn new_connections_per_ip_are_rate_limited() {
        let t = table(AbuseLimits {
            connections_per_ip_per_minute: 3,
            ..AbuseLimits::default()
        });
        let now = Instant::now();
        for _ in 0..3 {
            drop(t.connect(ip("192.0.2.1"), now).unwrap());
        }
        let Err(Refused::Rate(wait)) = t.connect(ip("192.0.2.1"), now) else {
            panic!("the fourth connection in a minute")
        };
        assert_eq!(wait, Duration::from_secs(20));
        assert!(t.connect(ip("192.0.2.2"), now).is_ok(), "another IP");
        assert!(t.connect(ip("192.0.2.1"), now + wait).is_ok());
    }

    #[test]
    fn admin_requests_per_ip_are_rate_limited() {
        let t = table(AbuseLimits {
            admin_requests_per_ip_per_minute: 2,
            ..AbuseLimits::default()
        });
        let now = Instant::now();
        assert!(t.admin_request(ip("192.0.2.1"), now).is_ok());
        assert!(t.admin_request(ip("192.0.2.1"), now).is_ok());
        assert_eq!(
            t.admin_request(ip("192.0.2.1"), now),
            Err(Duration::from_secs(30))
        );
        assert!(t.admin_request(ip("192.0.2.2"), now).is_ok(), "another IP");
        // Connections and admin requests are counted apart.
        assert!(t.connect(ip("192.0.2.1"), now).is_ok());
    }

    #[test]
    fn open_connections_per_ip_are_capped_and_released() {
        let t = table(AbuseLimits {
            connections_per_ip_per_minute: 0,
            max_connections_per_ip: 2,
            ..AbuseLimits::default()
        });
        let now = Instant::now();
        let a = t.connect(ip("192.0.2.1"), now).unwrap();
        let _b = t.connect(ip("192.0.2.1"), now).unwrap();
        assert_eq!(
            t.connect(ip("192.0.2.1"), now).unwrap_err(),
            Refused::TooMany
        );
        assert!(t.connect(ip("192.0.2.2"), now).is_ok(), "another IP");
        drop(a);
        assert!(
            t.connect(ip("192.0.2.1"), now).is_ok(),
            "a place was released"
        );
        let off = table(AbuseLimits {
            max_connections_per_ip: 0,
            connections_per_ip_per_minute: 0,
            ..AbuseLimits::default()
        });
        let held: Vec<_> = (0..100)
            .map(|_| off.connect(ip("192.0.2.1"), now).unwrap())
            .collect();
        assert_eq!(held.len(), 100, "0 disables the cap");
    }

    #[test]
    fn an_ip_spraying_flood_cannot_grow_the_table() {
        let cap = 1024;
        let t = table(AbuseLimits {
            max_tracked_ips: cap,
            max_connections_per_ip: 3,
            ..AbuseLimits::default()
        });
        let now = Instant::now();
        // Connections that stay open are never evicted.
        let held: Vec<_> = (0..100u32)
            .map(|i| {
                t.connect(IpAddr::V4((0x0a00_0000 + i).into()), now)
                    .unwrap()
            })
            .collect();
        for i in 0..100_000u32 {
            let ip = IpAddr::V6((0x2001_0db8_u128 << 96 | u128::from(i) << 64).into());
            drop(t.connect(ip, now).unwrap());
            assert!(t.len() <= cap, "{} entries after {i}", t.len());
        }
        // The open ones are still counted (each sprayed entry had a
        // half-used rate bucket, so it was evicted by age, not as idle).
        let ten = IpAddr::V4(0x0a00_0000.into());
        let more: Vec<_> = (1..3).map(|_| t.connect(ten, now).unwrap()).collect();
        assert_eq!(t.connect(ten, now).unwrap_err(), Refused::TooMany);
        drop((held, more));
    }

    #[test]
    fn defaults_are_valid() {
        assert_eq!(AbuseLimits::default().validate(), Ok(()));
    }
}
