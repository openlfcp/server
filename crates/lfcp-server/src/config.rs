//! Server configuration: a TOML file, a few command-line overrides, and
//! typed validation.
//!
//! ```toml
//! bind = "127.0.0.1:7820"          # HTTP and (from LFCP-047) WebSocket listener
//! ws_path = "/v1/ws"              # WebSocket path (WIRE-01 §30)
//! state_dir = "state"              # server ID, later the database
//! max_message_bytes = 8388608      # advertised in READY (WIRE-01 §31, §37)
//! heartbeat_ms = 30000             # READY heartbeat (§37); 0 disables the idle timeout
//! handshake_timeout_ms = 10000     # HTTP request headers and the LFCP handshake (to READY)
//! max_connections = 1024           # open TCP connections; more get HTTP 503
//! public_urls = ["wss://sync.example.org/v1/ws"]  # this server's WebSocket URLs (§21)
//! log_level = "info"               # error | warn | info | debug | trace
//! # Abuse limits (POST-003; crate::limits). 0 disables a per-IP or rate limit.
//! trusted_proxies = ["172.18.0.0/16"]   # peers whose client_ip_header is believed
//! client_ip_header = "x-forwarded-for"  # or "x-real-ip", "cf-connecting-ip"
//! max_connections_per_ip = 32           # open WebSockets per client IP
//! connections_per_ip_per_minute = 20    # new WebSockets per client IP
//! ws_messages_per_second = 50           # per connection, token bucket
//! ws_message_burst = 200
//! admin_requests_per_ip_per_minute = 60 # /setup and /admin/*
//! max_tracked_ips = 65536               # bounded per-IP state
//! quota_resources_per_principal = 20    # quota hosting mode
//! quota_bytes_per_principal = 268435456
//! quota_bytes_per_resource = 134217728
//! hosts_per_ip_per_day = 10
//! max_total_bytes = 3221225472          # every mode; unset: no cap
//! min_free_bytes = 2147483648           # every mode; 0 disables
//! disk_check_interval_ms = 10000
//! ```
//!
//! Every field has a default; unknown fields are rejected. There is no
//! hosted-service account configuration.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::limits::{AbuseLimits, Cidr};

/// The smallest maximum message size the server accepts: enough for any
/// MVP message and far below the 8 MiB default (WIRE-01 §31).
pub const MIN_MESSAGE_BYTES: usize = 64 * 1024;

/// The largest one, so a configuration typo cannot make the server buffer
/// unbounded messages.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// The largest `max_connections`.
pub const MAX_CONNECTIONS: usize = 1_000_000;

/// A validated configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The listener address.
    pub bind: SocketAddr,
    /// The WebSocket path (WIRE-01 §30 reference path `/v1/ws`).
    pub ws_path: String,
    /// The directory for the server's local state.
    pub state_dir: PathBuf,
    /// The maximum LFCP message size the server enforces and advertises.
    pub max_message_bytes: usize,
    /// The heartbeat interval advertised in READY (§37), in milliseconds; a
    /// WebSocket connection silent for three intervals is closed. 0
    /// disables both.
    pub heartbeat_ms: u64,
    /// How long a client may take to send its HTTP request headers, and a
    /// WebSocket connection to reach READY (§37); then it is closed.
    pub handshake_timeout_ms: u64,
    /// The most TCP connections (HTTP and WebSocket) open at once; past it
    /// a new connection gets HTTP 503 and is closed.
    pub max_connections: usize,
    /// The WebSocket URLs clients reach this server at. A Resource whose
    /// Control Coordinator URL (§15, §20) names one of them, compared after
    /// [`crate::coordinator::normalize_url`], is coordinated here (§21);
    /// empty means this server coordinates no Resource.
    pub public_urls: Vec<String>,
    /// The log level.
    pub log_level: tracing::Level,
    /// The abuse limits (POST-003).
    pub abuse: AbuseLimits,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: SocketAddr::from(([127, 0, 0, 1], 7820)),
            ws_path: "/v1/ws".into(),
            state_dir: PathBuf::from("state"),
            max_message_bytes: lfcp::wire::message::DEFAULT_MAX_MESSAGE_BYTES,
            heartbeat_ms: 30_000,
            handshake_timeout_ms: 10_000,
            max_connections: 1024,
            public_urls: Vec::new(),
            log_level: tracing::Level::INFO,
            abuse: AbuseLimits::default(),
        }
    }
}

/// Why a configuration is invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The file or a flag could not be read.
    Read(String),
    /// The TOML does not parse, or has an unknown field or a wrong type.
    Syntax(String),
    /// A field has an invalid value.
    Invalid {
        /// The field.
        field: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// A command-line argument is not understood.
    Usage(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(e) => write!(f, "cannot read configuration: {e}"),
            ConfigError::Syntax(e) => write!(f, "configuration: {e}"),
            ConfigError::Invalid { field, reason } => write!(f, "configuration {field}: {reason}"),
            ConfigError::Usage(e) => write!(f, "{e}\n\n{USAGE}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The command-line help.
pub const USAGE: &str = "usage: lfcp-server [--health-check] [--config FILE] [--bind ADDR:PORT] [--state-dir DIR] [--log-level LEVEL]

  --health-check  probe GET /health of the server this configuration
                  describes and exit 0 if it answers 200 (for containers)";

/// The configuration file as written: every field optional.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    bind: Option<String>,
    ws_path: Option<String>,
    state_dir: Option<PathBuf>,
    max_message_bytes: Option<u64>,
    heartbeat_ms: Option<u64>,
    handshake_timeout_ms: Option<u64>,
    max_connections: Option<u64>,
    public_urls: Option<Vec<String>>,
    log_level: Option<String>,
    // The abuse limits (POST-003).
    trusted_proxies: Option<Vec<String>>,
    client_ip_header: Option<String>,
    max_connections_per_ip: Option<u64>,
    connections_per_ip_per_minute: Option<u32>,
    ws_messages_per_second: Option<u32>,
    ws_message_burst: Option<u32>,
    admin_requests_per_ip_per_minute: Option<u32>,
    max_tracked_ips: Option<u64>,
    quota_resources_per_principal: Option<u64>,
    quota_bytes_per_principal: Option<u64>,
    quota_bytes_per_resource: Option<u64>,
    hosts_per_ip_per_day: Option<u32>,
    max_total_bytes: Option<u64>,
    min_free_bytes: Option<u64>,
    disk_check_interval_ms: Option<u64>,
}

impl Config {
    /// Parse a TOML configuration over the defaults.
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let file: File =
            toml::from_str(text).map_err(|e| ConfigError::Syntax(e.message().to_owned()))?;
        let mut config = Config {
            abuse: abuse_limits(&file)?,
            ..Config::default()
        };
        if let Some(bind) = file.bind {
            config.bind = parse_bind(&bind)?;
        }
        if let Some(path) = file.ws_path {
            config.ws_path = path;
        }
        if let Some(dir) = file.state_dir {
            config.state_dir = dir;
        }
        if let Some(bytes) = file.max_message_bytes {
            config.max_message_bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        }
        if let Some(ms) = file.heartbeat_ms {
            config.heartbeat_ms = ms;
        }
        if let Some(ms) = file.handshake_timeout_ms {
            config.handshake_timeout_ms = ms;
        }
        if let Some(n) = file.max_connections {
            config.max_connections = usize::try_from(n).unwrap_or(usize::MAX);
        }
        if let Some(urls) = file.public_urls {
            config.public_urls = urls;
        }
        if let Some(level) = file.log_level {
            config.log_level = parse_level(&level)?;
        }
        config.validate()?;
        Ok(config)
    }

    /// Build the configuration from command-line arguments (without the
    /// program name): `--config FILE` is read first, then the other flags
    /// override it.
    pub fn from_args<I: IntoIterator<Item = String>>(args: I) -> Result<Config, ConfigError> {
        let mut args = args.into_iter();
        let mut file = None;
        let mut overrides = Vec::new();
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| ConfigError::Usage(format!("{flag} needs a value")))
            };
            match flag.as_str() {
                "--config" => file = Some(value()?),
                "--bind" | "--state-dir" | "--log-level" => {
                    let v = value()?;
                    overrides.push((flag, v));
                }
                other => return Err(ConfigError::Usage(format!("unknown argument {other}"))),
            }
        }
        let mut config = match file {
            Some(path) => {
                let text = std::fs::read_to_string(&path)
                    .map_err(|e| ConfigError::Read(format!("{path}: {e}")))?;
                Config::from_toml(&text)?
            }
            None => Config::default(),
        };
        for (flag, value) in overrides {
            match flag.as_str() {
                "--bind" => config.bind = parse_bind(&value)?,
                "--state-dir" => config.state_dir = PathBuf::from(value),
                _ => config.log_level = parse_level(&value)?,
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// The rules every field must meet.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |field, reason: &str| {
            Err(ConfigError::Invalid {
                field,
                reason: reason.into(),
            })
        };
        if !self.ws_path.starts_with('/') || self.ws_path.chars().any(char::is_whitespace) {
            return invalid("ws_path", "must start with / and contain no whitespace");
        }
        if self.ws_path == crate::http::HEALTH_PATH {
            return invalid("ws_path", "must differ from the health path");
        }
        if self.state_dir.as_os_str().is_empty() {
            return invalid("state_dir", "must not be empty");
        }
        if self.heartbeat_ms > 0 && !(1_000..=3_600_000).contains(&self.heartbeat_ms) {
            return invalid("heartbeat_ms", "must be 0 or between 1000 and 3600000");
        }
        if !(1_000..=600_000).contains(&self.handshake_timeout_ms) {
            return invalid("handshake_timeout_ms", "must be between 1000 and 600000");
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return invalid("max_connections", "must be between 1 and 1000000");
        }
        if !(MIN_MESSAGE_BYTES..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes) {
            return invalid("max_message_bytes", "must be between 65536 and 67108864");
        }
        if self
            .public_urls
            .iter()
            .any(|url| crate::coordinator::normalize_url(url).is_none())
        {
            return invalid(
                "public_urls",
                "each must be an absolute ws:// or wss:// URL without user info or fragment",
            );
        }
        if let Err((field, reason)) = self.abuse.validate() {
            return invalid(field, reason);
        }
        Ok(())
    }
}

/// The abuse limits of `file` over their defaults.
fn abuse_limits(file: &File) -> Result<AbuseLimits, ConfigError> {
    let mut limits = AbuseLimits::default();
    if let Some(proxies) = &file.trusted_proxies {
        limits.trusted_proxies = proxies
            .iter()
            .map(|p| p.parse::<Cidr>())
            .collect::<Result<_, _>>()
            .map_err(|e| ConfigError::Invalid {
                field: "trusted_proxies",
                reason: e.to_string(),
            })?;
    }
    if let Some(header) = &file.client_ip_header {
        limits.client_ip_header = header.to_ascii_lowercase();
    }
    let size = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    let set = |slot: &mut u32, value: Option<u32>| {
        if let Some(value) = value {
            *slot = value;
        }
    };
    if let Some(n) = file.max_connections_per_ip {
        limits.max_connections_per_ip = size(n);
    }
    set(
        &mut limits.connections_per_ip_per_minute,
        file.connections_per_ip_per_minute,
    );
    set(
        &mut limits.ws_messages_per_second,
        file.ws_messages_per_second,
    );
    set(&mut limits.ws_message_burst, file.ws_message_burst);
    set(
        &mut limits.admin_requests_per_ip_per_minute,
        file.admin_requests_per_ip_per_minute,
    );
    set(&mut limits.hosts_per_ip_per_day, file.hosts_per_ip_per_day);
    if let Some(n) = file.max_tracked_ips {
        limits.max_tracked_ips = size(n);
    }
    if let Some(n) = file.quota_resources_per_principal {
        limits.quota_resources_per_principal = n;
    }
    if let Some(n) = file.quota_bytes_per_principal {
        limits.quota_bytes_per_principal = n;
    }
    if let Some(n) = file.quota_bytes_per_resource {
        limits.quota_bytes_per_resource = n;
    }
    if file.max_total_bytes.is_some() {
        limits.max_total_bytes = file.max_total_bytes;
    }
    if let Some(n) = file.min_free_bytes {
        limits.min_free_bytes = n;
    }
    if let Some(ms) = file.disk_check_interval_ms {
        limits.disk_check_interval_ms = ms;
    }
    Ok(limits)
}

fn parse_bind(text: &str) -> Result<SocketAddr, ConfigError> {
    text.parse().map_err(|_| ConfigError::Invalid {
        field: "bind",
        reason: format!("{text:?} is not an IP address and port"),
    })
}

fn parse_level(text: &str) -> Result<tracing::Level, ConfigError> {
    match text {
        "error" | "warn" | "info" | "debug" | "trace" => Ok(text.parse().expect("a known level")),
        _ => Err(ConfigError::Invalid {
            field: "log_level",
            reason: format!("{text:?} is not error, warn, info, debug or trace"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn defaults_are_valid_and_local() {
        let config = Config::default();
        assert_eq!(config.validate(), Ok(()));
        assert!(config.bind.ip().is_loopback());
        assert_eq!(config.max_message_bytes, 8 * 1024 * 1024);
        assert_eq!(Config::from_toml(""), Ok(config));
    }

    #[test]
    fn parses_every_field() {
        let config = Config::from_toml(
            "bind = \"0.0.0.0:9000\"\nws_path = \"/ws\"\nstate_dir = \"/var/lib/lfcp\"\nmax_message_bytes = 1048576\nheartbeat_ms = 0\nhandshake_timeout_ms = 5000\nmax_connections = 64\npublic_urls = [\"wss://sync.example.org/v1/ws\"]\nlog_level = \"debug\"\n",
        )
        .unwrap();
        assert_eq!(config.bind, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(config.ws_path, "/ws");
        assert_eq!(config.state_dir, PathBuf::from("/var/lib/lfcp"));
        assert_eq!(config.max_message_bytes, 1 << 20);
        assert_eq!(config.heartbeat_ms, 0);
        assert_eq!(config.handshake_timeout_ms, 5_000);
        assert_eq!(config.max_connections, 64);
        assert_eq!(config.public_urls, vec!["wss://sync.example.org/v1/ws"]);
        assert_eq!(config.log_level, tracing::Level::DEBUG);
    }

    #[test]
    fn rejects_invalid_configuration() {
        let field = |text: &str| match Config::from_toml(text) {
            Err(ConfigError::Invalid { field, .. }) => field,
            other => panic!("{text}: {other:?}"),
        };
        assert_eq!(field("bind = \"localhost\""), "bind");
        assert_eq!(field("ws_path = \"lfcp\""), "ws_path");
        assert_eq!(field("ws_path = \"/health\""), "ws_path");
        assert_eq!(field("state_dir = \"\""), "state_dir");
        assert_eq!(field("max_message_bytes = 0"), "max_message_bytes");
        assert_eq!(field("max_message_bytes = 1073741824"), "max_message_bytes");
        assert_eq!(field("log_level = \"loud\""), "log_level");
        assert_eq!(field("heartbeat_ms = 10"), "heartbeat_ms");
        assert_eq!(field("handshake_timeout_ms = 0"), "handshake_timeout_ms");
        assert_eq!(field("max_connections = 0"), "max_connections");
        assert_eq!(field("max_connections = 1000001"), "max_connections");
        assert_eq!(
            field("handshake_timeout_ms = 600001"),
            "handshake_timeout_ms"
        );
        assert_eq!(field("public_urls = [\"https://x/v1/ws\"]"), "public_urls");
        assert_eq!(field("public_urls = [\"wss://u@x/v1/ws\"]"), "public_urls");
        assert!(matches!(
            Config::from_toml("bind = 7"),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            Config::from_toml("account = \"x\""),
            Err(ConfigError::Syntax(_))
        ));
        assert!(matches!(
            Config::from_toml("bind = "),
            Err(ConfigError::Syntax(_))
        ));
    }

    #[test]
    fn parses_the_abuse_limits() {
        let config = Config::from_toml(
            "trusted_proxies = [\"172.18.0.0/16\", \"10.0.0.2\", \"fd00::/8\"]\nclient_ip_header = \"CF-Connecting-IP\"\nmax_connections_per_ip = 4\nconnections_per_ip_per_minute = 0\nws_messages_per_second = 10\nws_message_burst = 20\nadmin_requests_per_ip_per_minute = 5\nmax_tracked_ips = 2048\nquota_resources_per_principal = 3\nquota_bytes_per_principal = 1000\nquota_bytes_per_resource = 500\nhosts_per_ip_per_day = 2\nmax_total_bytes = 3221225472\nmin_free_bytes = 0\ndisk_check_interval_ms = 1000\n",
        )
        .unwrap();
        let abuse = &config.abuse;
        let proxies: Vec<String> = abuse.trusted_proxies.iter().map(Cidr::to_string).collect();
        assert_eq!(proxies, ["172.18.0.0/16", "10.0.0.2/32", "fd00::/8"]);
        assert_eq!(abuse.client_ip_header, "cf-connecting-ip");
        assert_eq!(abuse.max_connections_per_ip, 4);
        assert_eq!(abuse.connections_per_ip_per_minute, 0);
        assert_eq!(
            (abuse.ws_messages_per_second, abuse.ws_message_burst),
            (10, 20)
        );
        assert_eq!(abuse.admin_requests_per_ip_per_minute, 5);
        assert_eq!(abuse.max_tracked_ips, 2048);
        assert_eq!(abuse.quota_resources_per_principal, 3);
        assert_eq!(abuse.quota_bytes_per_principal, 1000);
        assert_eq!(abuse.quota_bytes_per_resource, 500);
        assert_eq!(abuse.hosts_per_ip_per_day, 2);
        assert_eq!(abuse.max_total_bytes, Some(3 << 30));
        assert_eq!(abuse.min_free_bytes, 0);
        assert_eq!(abuse.disk_check_interval_ms, 1000);

        let defaults = Config::default().abuse;
        assert!(defaults.trusted_proxies.is_empty());
        assert_eq!(defaults.client_ip_header, "x-forwarded-for");
        assert_eq!(defaults.max_connections_per_ip, 32);
        assert_eq!(defaults.connections_per_ip_per_minute, 20);
        assert_eq!(
            (defaults.ws_messages_per_second, defaults.ws_message_burst),
            (50, 200)
        );
        assert_eq!(defaults.admin_requests_per_ip_per_minute, 60);
        assert_eq!(defaults.quota_resources_per_principal, 20);
        assert_eq!(defaults.quota_bytes_per_principal, 256 << 20);
        assert_eq!(defaults.quota_bytes_per_resource, 128 << 20);
        assert_eq!(defaults.hosts_per_ip_per_day, 10);
        assert_eq!(defaults.max_total_bytes, None);
        assert_eq!(defaults.min_free_bytes, 2 << 30);
    }

    #[test]
    fn rejects_invalid_abuse_limits() {
        let field = |text: &str| match Config::from_toml(text) {
            Err(ConfigError::Invalid { field, .. }) => field,
            other => panic!("{text}: {other:?}"),
        };
        assert_eq!(
            field("trusted_proxies = [\"10.0.0.0/40\"]"),
            "trusted_proxies"
        );
        assert_eq!(field("trusted_proxies = [\"proxy\"]"), "trusted_proxies");
        assert_eq!(
            field("client_ip_header = \"x forwarded\""),
            "client_ip_header"
        );
        assert_eq!(
            field("ws_messages_per_second = 5\nws_message_burst = 0"),
            "ws_message_burst"
        );
        assert_eq!(
            field("connections_per_ip_per_minute = 1000001"),
            "connections_per_ip_per_minute"
        );
        assert_eq!(field("max_tracked_ips = 10"), "max_tracked_ips");
        assert_eq!(
            field("quota_resources_per_principal = 0"),
            "quota_resources_per_principal"
        );
        assert_eq!(
            field("quota_bytes_per_resource = 0"),
            "quota_bytes_per_resource"
        );
        assert_eq!(field("max_total_bytes = 0"), "max_total_bytes");
        assert_eq!(
            field("disk_check_interval_ms = 1"),
            "disk_check_interval_ms"
        );
    }

    #[test]
    fn flags_override_the_file() {
        let dir = std::env::temp_dir().join(format!("lfcp-server-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.toml");
        std::fs::write(&path, "bind = \"127.0.0.1:1000\"\nlog_level = \"warn\"\n").unwrap();
        let config = Config::from_args(args(&[
            "--config",
            path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:2000",
            "--state-dir",
            "elsewhere",
        ]))
        .unwrap();
        assert_eq!(config.bind.port(), 2000);
        assert_eq!(config.state_dir, PathBuf::from("elsewhere"));
        assert_eq!(config.log_level, tracing::Level::WARN);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(matches!(
            Config::from_args(args(&["--port", "1"])),
            Err(ConfigError::Usage(_))
        ));
        assert!(matches!(
            Config::from_args(args(&["--bind"])),
            Err(ConfigError::Usage(_))
        ));
        assert!(matches!(
            Config::from_args(args(&["--config", "/nonexistent/x.toml"])),
            Err(ConfigError::Read(_))
        ));
        assert!(matches!(
            Config::from_args(args(&["--log-level", "loud"])),
            Err(ConfigError::Invalid {
                field: "log_level",
                ..
            })
        ));
    }
}
