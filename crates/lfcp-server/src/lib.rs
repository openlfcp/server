//! The OpenLFCP reference server: an application-agnostic LFCP
//! synchronization peer, built on the `lfcp` crate of sdk-rs (protocol core
//! only, no Shared Objects or Automerge).
//!
//! | Module | Purpose | Task |
//! | --- | --- | --- |
//! | [`config`] | TOML configuration and flags, typed validation | LFCP-044 |
//! | [`identity`] | the stable server ID (WIRE-01 §35, §37) | LFCP-044 |
//! | [`rng`] | operating-system randomness | LFCP-044 |
//! | [`http`] | the health endpoint | LFCP-044 |
//! | [`server`] | listener, connections, graceful shutdown | LFCP-044 |
//! | [`store`] | the SQLite store of exact LFCP objects | LFCP-045 |
//! | [`ws`] | the LFCP WebSocket transport: framing, limits, session hook | LFCP-047 |
//! | [`session`] | the LFCP session: handshake, Resource host/open/close | LFCP-048 |
//!
//! Later tasks add setup/admin HTTP (LFCP-046) and the Control, Data, Key
//! and Snapshot planes (LFCP-049 onward). The server never understands Markdown, Tasks or
//! Automerge, and never logs keys, DEKs, invitation secrets, credentials or
//! decrypted data.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod http;
pub mod identity;
pub mod rng;
pub mod server;
pub mod session;
pub mod store;
pub mod ws;
