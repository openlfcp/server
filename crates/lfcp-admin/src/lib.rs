//! `lfcp-admin`: the administration client of the OpenLFCP reference
//! server (POST-014). It holds the administrator's LFCP Principal key and
//! signs the admin proofs the server's setup/admin HTTP API asks for
//! (`lfcp_server::admin`): the first-run pairing, then one admin session
//! per command for the status, the hosting policy and quota overrides.
//!
//! | Module | Purpose |
//! | --- | --- |
//! | [`key`] | the admin key file: created 0600, refused when others can read it |
//! | [`http`] | a minimal blocking HTTP/1.1 client, plain `http://` only |
//! | [`client`] | challenges, proofs, sessions and the admin calls |
//!
//! The server's admin API listens on its loopback port, reached over an
//! SSH tunnel, so there is no TLS here: an `https://` URL is refused.
//! Secrets (the key, the setup code, session tokens) are never printed or
//! logged.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod http;
pub mod key;

use std::fmt;

/// Why a command failed. Each prints as one human-readable line.
#[derive(Debug)]
pub enum Error {
    /// The command line is wrong.
    Usage(String),
    /// A local file or the network failed.
    Io(String),
    /// The server refused the request: its HTTP status and error message.
    Refused {
        /// The HTTP status.
        status: u16,
        /// The server's `error` text.
        message: String,
        /// `Retry-After` seconds, if the server sent it.
        retry_after: Option<String>,
    },
    /// The server's answer is not what the admin API defines.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(e) => write!(f, "{e}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Refused {
                status,
                message,
                retry_after,
            } => {
                write!(f, "the server refused: {message} (HTTP {status})")?;
                if let Some(seconds) = retry_after {
                    write!(f, "; retry after {seconds} s")?;
                }
                Ok(())
            }
            Error::Protocol(e) => write!(f, "unexpected answer from the server: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// The process exit status: 2 for usage errors, 1 otherwise.
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Usage(_) => 2,
            _ => 1,
        }
    }
}
