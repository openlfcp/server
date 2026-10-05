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
- WebSocket transport (LFCP-047): framing, limits and shutdown.
- Session (LFCP-048): HELLO / CHALLENGE / AUTH / READY, and
  RESOURCE_HOST, RESOURCE_OPEN and RESOURCE_CLOSE.
- Control Coordinator (LFCP-049): CONTROL_PUT compare-and-swap,
  CONTROL_HAVE / GET / BATCH, live Control pushes.
- Ingest (LFCP-050): Data Units, Key Packages and Snapshots validated
  with sdk-rs and served to readers; live Data pushes.

Next: setup and admin HTTP (LFCP-046) and equivocation policy (LFCP-052).

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
| `public_urls` | | `[]` | This server's WebSocket URLs: it coordinates the Resources whose Control Coordinator URL is one of them (WIRE-01 §21) |
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
  created per connection by a `ws::SessionFactory`); the server runs the
  LFCP session below.
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

## Session

`session::Lfcp` runs the WIRE-01 §64 server session with sdk-rs
(`select_wire_profile`, `verify_auth`, `server_accepts`, the
`ServerSession` machine). Nonces, session IDs and message IDs come from the
server's random source; the server ID from `<state_dir>/server-id`.

| Situation | Answer |
| --- | --- |
| HELLO with an invalid descriptor or an ID that is not its keys' hash | `ERROR(AUTH_FAILED)`, close |
| HELLO with no wire profile in common | `ERROR(PROTOCOL_UNSUPPORTED)`, close |
| AUTH proof that fails in any way | `ERROR(AUTH_FAILED)`, close |
| Resource, Control, Data, Key or Snapshot message before READY | `NACK(AUTHORIZATION_FAILED)`, stays open |
| PING / PONG / ERROR before READY | allowed |
| a handshake message out of order, anything else before READY, or an undecodable message before READY | `ERROR(MALFORMED_MESSAGE)`, close |
| READY | the profile, server ID, `max_message_bytes`, durability 2, `heartbeat_ms`, no extensions |

After READY:

- `RESOURCE_HOST`: sdk-rs validates the Genesis (sequence 0, signed by the
  owner in its body, ws/wss URLs), the hosting policy is applied, the
  Genesis is committed to the store, and only then `RESOURCE_HOSTED`
  (durability 2) is sent. Hosting the same Genesis again succeeds; another
  Genesis for the same Resource is `NACK(CONTROL_CONFLICT)`.
- `RESOURCE_OPEN`: a Resource this server does not host is
  `NACK(RESOURCE_NOT_HOSTED)`. The server validates the stored chain up to
  its accepted head with the sdk-rs capability engine (a chain with a
  Coordinator Recovery or Tombstone is refused in MVP) and requires the
  session Principal to hold `data/read` there, or to be the subject of an
  invitation grant that still confers `invite/claim` (WIRE-01 §84, §41,
  §73); otherwise `NACK(AUTHORIZATION_FAILED)`. `RESOURCE_OPENED` carries
  every Control Head the server knows (a fork is not hidden), its Have, a
  summary of the newest stored Snapshot, the route version and the
  coordinator.
- `RESOURCE_CLOSE`: drops the session's subscription and answers `ACK`;
  stored data is untouched.
- Presence and mirror seeding (client `CONTROL_BATCH`, `DATA_BATCH`,
  `KEY_PACKAGE_BATCH`, `SNAPSHOT`): `NACK(PROTOCOL_UNSUPPORTED)`.

Authority: AUTH proves possession of the session key and nothing more. The
hosting credential (in AUTH or RESOURCE_HOST) is server policy only
(`session::HostingPolicy`); the self-hosted default, `OpenHosting`, lets any
authenticated Principal host, with or without one. Neither a credential nor
the hosting row ever grants a Resource ability: authority always comes from
the Control Chain. Credentials and proofs are never logged.

## Control Coordinator

`CONTROL_PUT` (WIRE-01 §47) is accepted only where this server is the
Resource's current Control Coordinator: the coordinator URL of the last
Genesis or Route Update on the accepted chain must equal one of
`public_urls` after normalization (scheme and host lower-cased, default
port dropped, empty path as `/`; host names are not resolved, so list
every name the server is reached by). Otherwise the answer is
`NACK(NOT_CONTROL_COORDINATOR)` with the coordinator URL as details. With
no `public_urls`, the server coordinates nothing.

Then sdk-rs `propose_transition` checks the expected head, placement,
signature and authority against the cached Control state at the head
(one-time claims included), and the store commits the record and the new
head in one SQLite transaction that re-checks the expected head. Puts for
one Resource are serialized; the `ACK` (`request_type` 23, the record ID,
`durable: true`) follows the commit.

| Situation | Answer |
| --- | --- |
| expected head is not the current head | `NACK(CONTROL_HEAD_MISMATCH)`, details = the current head ID |
| null expected head | does not decode: `ERROR(MALFORMED_MESSAGE)` |
| Genesis | `NACK(MALFORMED_MESSAGE)` (use RESOURCE_HOST) |
| sequence or previous record wrong, unknown core type | `NACK(INVALID_CONTROL_CHAIN)` |
| signature | `NACK(INVALID_SIGNATURE)` |
| issuer unknown to the chain | `NACK(MISSING_DEPENDENCY)` |
| no authority, escalation, used-up claim, revoking a revoked grant | `NACK(AUTHORIZATION_FAILED)` |
| Coordinator Recovery, Resource Tombstone (deferred) | `NACK(PROTOCOL_UNSUPPORTED)` |
| the record is already on the chain | the same `ACK` again |

A put that loses the compare-and-swap is not stored: it is a refused
proposal, not fork evidence, and storing it would show clients a fork the
coordinator prevented.

After a commit the record goes, as a one-record `CONTROL_BATCH`, to every
other session that opened the Resource with live Control pushes (flag bit
1). A push never waits: a session whose queue is full is closed (1013)
instead of silently missing records. `CONTROL_HAVE` and `CONTROL_GET` need
the same read authority as `RESOURCE_OPEN`; `CONTROL_GET` returns every
stored record in the range, competing ones included, split over several
`CONTROL_BATCH` replies when the size limit requires.

## Ingest

`DATA_PUT`, `KEY_PACKAGE_PUT` and `SNAPSHOT_PUT` objects are validated
with sdk-rs against the Resource's accepted Control Chain (`ingest`), all
of a put before any is stored: one invalid object refuses the put. The
server never decrypts and never holds a DEK.

| Check | Failure |
| --- | --- |
| canonical COSE, closed payload, the request's Resource ID, sequence ≥ 1 | `MALFORMED_MESSAGE` |
| signer (actor, sender, publisher) unknown to the chain; referenced head not on it; epoch unknown there | `MISSING_DEPENDENCY` |
| `kid` = signer, strict Ed25519 | `INVALID_SIGNATURE` |
| Data Unit: `data/write` at its referenced head (an older head is fine) | `AUTHORIZATION_FAILED` |
| Data Unit: a closed epoch beyond the actor's cutoff (latest state) | `STALE_DATA_EPOCH` |
| Key Package: sender `key/distribute`, recipient `data/read` or an invitation subject, at its head | `AUTHORIZATION_FAILED` |
| Snapshot: `snapshot/publish` at its head; a closed epoch's frontier beyond the cutoff | `AUTHORIZATION_FAILED`, `STALE_DATA_EPOCH` |
| `ingest::IngestPolicy` (quotas, rate limits; unlimited by default) | `QUOTA_EXCEEDED`, `RATE_LIMITED` |

AEAD failures, an HPKE package sealed to someone else and actor hash chain
gaps are detectable only by clients and are accepted. A Data Unit that
equivocates (another signature-valid unit at its actor and sequence) is
stored as evidence and the put is answered `NACK(ACTOR_EQUIVOCATION)`.
Otherwise the `ACK` (`request_type` 33, 42 or 52, every object ID,
`durable: true`) follows the commit; repeated puts get the same `ACK`.

Ingest for a Resource holds its coordinator lock, so an object is never
validated against a head that a concurrent Key Epoch or Revoke has
superseded.

Reads (`DATA_HAVE`, `DATA_GET`, `KEY_PACKAGE_GET`, `SNAPSHOT_GET`) need
read authority at the accepted head; Key Packages go only to their
recipient. Newly accepted Data Units go as a `DATA_BATCH` to other
sessions that opened the Resource with live Data pushes (flag bit 0).
After every Control commit, subscribers that lost read authority are
dropped from live pushes; their session stays open and its next request
for the Resource gets `AUTHORIZATION_FAILED`.

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
