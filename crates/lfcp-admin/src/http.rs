//! A minimal blocking HTTP/1.1 client for the admin API: one request per
//! connection (`Connection: close`), JSON bodies, plain `http://` only.
//!
//! The admin API is meant for the server's loopback port, reached over an
//! SSH tunnel (`ssh -L 17820:127.0.0.1:17820 host`), so the tunnel is the
//! transport security and this client has no TLS.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::Value;

use crate::Error;

/// The default server URL: the server's port on loopback, as an SSH
/// tunnel forwards it.
pub const DEFAULT_URL: &str = "http://127.0.0.1:17820";

/// How long connecting, sending and reading may each take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer read.
const MAX_ANSWER: u64 = 1 << 20;

/// A parsed `http://host[:port][/prefix]` URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    host: String,
    port: u16,
    prefix: String,
}

impl Url {
    /// Parse `text`; only `http://` is accepted.
    pub fn parse(text: &str) -> Result<Url, Error> {
        let bad = |why: &str| Error::Usage(format!("--url {text:?}: {why}"));
        if text.starts_with("https://") {
            return Err(bad(
                "https is not supported; reach the server's loopback port over an SSH tunnel and use http://127.0.0.1:PORT",
            ));
        }
        let rest = text
            .strip_prefix("http://")
            .ok_or_else(|| bad("must start with http://"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(bad("needs a host, without user info"));
        }
        let bracketed = authority.starts_with('[') && authority.ends_with(']');
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !bracketed => {
                let port = port.parse().map_err(|_| bad("the port is not a number"))?;
                (host, port)
            }
            _ => (authority, 80),
        };
        Ok(Url {
            host: host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port,
            prefix: path.trim_end_matches('/').to_owned(),
        })
    }
}

/// A server's answer: its status, `Retry-After` and JSON body (`Null` when
/// the body is not JSON).
#[derive(Clone, Debug)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The `Retry-After` header, if any.
    pub retry_after: Option<String>,
    /// The JSON body.
    pub body: Value,
}

/// Send one request to `url` + `path`. A bearer token goes in
/// `Authorization`; it is never printed.
pub fn request(
    url: &Url,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> Result<Answer, Error> {
    let target = format!("{}:{}", url.host, url.port);
    let unreachable = |e: std::io::Error| {
        Error::Io(format!(
            "cannot reach the server at {target}: {e} (is the SSH tunnel up?)"
        ))
    };
    let addrs: Vec<_> = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(unreachable)?
        .collect();
    let mut last = None;
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let mut stream = stream
        .ok_or_else(|| unreachable(last.unwrap_or_else(|| std::io::Error::other("no address"))))?;
    let io = |e: std::io::Error| Error::Io(format!("talking to {target}: {e}"));
    stream.set_read_timeout(Some(TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(io)?;
    let body = body.map(Value::to_string).unwrap_or_default();
    let mut head = format!(
        "{method} {}{path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        url.prefix,
        body.len()
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(io)?;
    stream.write_all(body.as_bytes()).map_err(io)?;
    let mut raw = Vec::new();
    stream.take(MAX_ANSWER).read_to_end(&mut raw).map_err(io)?;
    parse_answer(&raw)
}

/// Parse a complete HTTP/1.1 answer.
fn parse_answer(raw: &[u8]) -> Result<Answer, Error> {
    let bad = |why: &str| Error::Protocol(why.to_owned());
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no complete HTTP answer"))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| bad("a non-UTF-8 header"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| {
            l.strip_prefix("HTTP/1.1 ")
                .or_else(|| l.strip_prefix("HTTP/1.0 "))
        })
        .and_then(|l| l.get(..3))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("no HTTP status line"))?;
    let mut retry_after = None;
    let mut length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "retry-after" => retry_after = Some(value.trim().to_owned()),
                "content-length" => length = value.trim().parse::<usize>().ok(),
                _ => {}
            }
        }
    }
    let mut body = &raw[split + 4..];
    if let Some(length) = length {
        body = &body[..length.min(body.len())];
    }
    Ok(Answer {
        status,
        retry_after,
        body: serde_json::from_slice(body).unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_plain_http_only() {
        let url = Url::parse("http://127.0.0.1:17820").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("127.0.0.1", 17820));
        assert_eq!(Url::parse("http://localhost").unwrap().port, 80);
        assert_eq!(Url::parse("http://h:1/base/").unwrap().prefix, "/base");
        let v6 = Url::parse("http://[::1]:7820").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("::1", 7820));
        assert_eq!(Url::parse("http://[::1]").unwrap().port, 80);
        for bad in [
            "https://sync.example.org",
            "ftp://x",
            "http://",
            "http://u@h:1",
            "http://h:x",
        ] {
            assert!(matches!(Url::parse(bad), Err(Error::Usage(_))), "{bad}");
        }
    }

    #[test]
    fn answers_parse() {
        let a = parse_answer(
            b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 20\r\ncontent-length: 13\r\n\r\n{\"error\":\"x\"}",
        )
        .unwrap();
        assert_eq!(a.status, 429);
        assert_eq!(a.retry_after.as_deref(), Some("20"));
        assert_eq!(a.body["error"], "x");
        let a = parse_answer(b"HTTP/1.1 404 Not Found\r\n\r\nnot found\n").unwrap();
        assert_eq!((a.status, a.body.clone()), (404, Value::Null));
        assert!(parse_answer(b"garbage").is_err());
    }
}
