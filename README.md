# openlfcp/server

The OpenLFCP reference server: an application-agnostic LFCP
synchronization peer in Rust, built on the `lfcp` crate of
[`sdk-rs`](https://github.com/openlfcp/sdk-rs).

The server stores and coordinates LFCP objects according to LFCP Wire. It is
a synchronization peer, not the root of trust: clients verify signatures and
authority themselves. It never understands Markdown, Obsidian, Tasks or
Automerge: it uses the `lfcp` protocol core without the `shared-objects`
feature, and `tests/dependency_policy.rs` fails if Automerge appears in its
dependency tree.

## Status

- Bootstrap (LFCP-044): configuration, the stable server ID, the health
  endpoint and graceful shutdown.
- Store (LFCP-045): SQLite persistence of exact LFCP objects.
- WebSocket transport (LFCP-047): framing, limits and shutdown; the only
  session so far answers PING.

Next: setup and admin HTTP (LFCP-046) and the LFCP session (LFCP-048).

## Store

`<state_dir>/server.sqlite3`, one connection owned by one thread behind an
async facade (`store::Store`): operations are serialized and every write is
acknowledged after its transaction commits.

- Durability: WAL journal with `synchronous = FULL`, so a committed write
  survives a crash or power loss (on storage that honors fsync). That backs
  durability level 2, durable local persistence (WIRE-01 §37, §40); the
  server does not replicate, so it never claims level 3.
- Exact bytes are authoritative: every Genesis, Control Record, Data Unit,
  Key Package and Snapshot is stored as received. Index columns (Resource,
  sequence, actor, epoch, recipient, Control Head, object IDs) are derived
  from those bytes by the sdk-rs parsers at insert time, never taken from a
  client separately.
- Evidence is kept: competing Control Records share a sequence, units with
  the same (Resource, actor, sequence) and different IDs are all stored
  (equivocation), and several Key Packages may exist for one (Resource,
  epoch, recipient). Only object IDs are unique.
- `commit_control_record` stores a record and moves the Control Head in
  one transaction, only if the head is the expected one and the record
  continues it (the compare-and-set that LFCP-049 builds on).
- Opaque: no table or column holds application data; Data Units and
  Snapshots are stored as ciphertext. Tests check both.
- Hosting metadata (who hosted a Resource here, the promised durability)
  is infrastructure only. Resource authority always comes from the stored
  Control Chain.
- Migrations: `schema_version` and an append-only list
  (`store/schema.rs`), applied in order when the database opens.

The server ID stays in its own file rather than in the database: it keeps
its create-new and fsync semantics, it is readable by an operator, and
recreating or restoring the database cannot change the server's identity.

## Running

```sh
cargo run -- --config server.toml
```

| Setting (TOML) | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `bind` | `--bind` | `127.0.0.1:7820` | Listener address |
| `ws_path` | | `/v1/ws` | WebSocket path (WIRE-01 §30) |
| `state_dir` | `--state-dir` | `state` | Local state: the server ID, later the database |
| `max_message_bytes` | | `8388608` | Maximum LFCP message size (WIRE-01 §31, §37) |
| `heartbeat_ms` | | `30000` | READY heartbeat (§37); a connection silent for three is closed. `0` disables, else 1000–3600000 |
| `log_level` | `--log-level` | `info` | `error`, `warn`, `info`, `debug` or `trace` |

`GET /health` answers `{"status":"ok"}` and nothing else. SIGINT or
SIGTERM stops accepting connections and gives open ones 10 seconds.

The server ID (WIRE-01 §35, §37) is 32 random bytes created on first start
in `<state_dir>/server-id` (mode 0600). It never changes afterwards, is the
same for every connection, and is never derived from the host name or an
address. A corrupt file stops the server instead of being replaced.

## WebSocket

`GET <ws_path>` upgrades to WebSocket with the `lfcp-1` subprotocol
(WIRE-01 §30). A request that does not offer `lfcp-1` gets 400, a wrong
WebSocket version 426.

- One binary WebSocket message is one LFCP message, decoded by sdk-rs
  (`Message::decode_frame`). The transport adds no protocol semantics: it
  hands each decoded message to the connection's session (`ws::Session`,
  created per connection by a `ws::SessionFactory`). LFCP-048 supplies the
  real session; until then `ws::PingOnly` answers PING with PONG, which
  WIRE-01 allows before READY (§64).
- A text frame gets `ERROR(MALFORMED_MESSAGE)` and close 1002 (§31).
- A message over `max_message_bytes` is refused from its frame header,
  before the payload is read or decoded: `ERROR(MESSAGE_TOO_LARGE)` and
  close 1009. The connection closes because the rest of the frame is
  unread.
- Other undecodable messages get `ERROR` with their code (malformed CBOR,
  an unknown type → `PROTOCOL_UNSUPPORTED`) and the connection stays open,
  unless sdk-rs says the error closes it.
- Outbound messages go through a bounded queue (256). A session whose
  `Outbound::send` finds it full is told (`Overloaded`) rather than
  buffering, and a write that takes longer than 10 s ends the connection,
  so a slow reader cannot grow memory.
- A connection that sends no LFCP message for three heartbeats is closed
  (1001). Only LFCP messages count, an LFCP `PING` included; WebSocket
  ping and pong frames do not.
- Shutdown sends every WebSocket close 1001, drains its queue, and waits
  within the same 10-second grace as HTTP connections.
- Logs carry the connection number, message types and error codes; never
  payloads.

The server speaks plain HTTP and WebSocket. Clients use `wss://` except on
loopback (WIRE-01 §16), so a deployment puts a TLS-terminating reverse
proxy in front (LFCP-055).

## Dependencies

| Crate | Why |
| --- | --- |
| `lfcp` (sdk-rs, path dependency) | The LFCP protocol core, default features only |
| `tokio` | Runtime, TCP, signals, timers |
| `hyper`, `hyper-util`, `http-body-util` | HTTP/1.1 server and the WebSocket upgrade |
| `tokio-tungstenite` (`handshake` only), `futures-util` (`sink`) | WebSocket framing |
| `getrandom` | The server ID; later nonces and session IDs |
| `tracing`, `tracing-subscriber` | Logs (level from the configuration) |
| `serde`, `toml` | The configuration file |
| `rusqlite` (bundled SQLite) | The store |

92 unique crates in the normal dependency tree. No web framework, no ORM,
no clap.

## sdk-rs and the spec

sdk-rs is consumed from a sibling checkout, `../sdk-rs`, as a path
dependency. `sdk-rs.lock` records the commit the server is built against;
`tests/sdk_rs_lock.rs` fails when the checkout is at another commit and
warns when the `lfcp` crate has uncommitted changes. Move the lock
deliberately when the server needs newer sdk-rs code. A git or tag
dependency replaces this at a release milestone.

`spec.lock` pins `openlfcp/spec` (`mvp-0.1-baseline.3`); tests read vectors
from `../spec` (or `$LFCP_SPEC_DIR`) with `git show` at the locked commit.

## Build from a clean checkout

With `sdk-rs` and `spec` checked out next to this repository:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Follow-ups

- Optional built-in TLS (a `rustls` feature) for a single-binary
  deployment without a reverse proxy.

## License

Apache License 2.0. See [LICENSE](LICENSE).
