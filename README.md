<picture><source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/openlfcp/.github/main/docs/assets/brand/openlfcp-mark-dark.svg"><img src="https://raw.githubusercontent.com/openlfcp/.github/main/docs/assets/brand/openlfcp-mark.svg" width="64" height="64" alt="OpenLFCP"></picture>

# openlfcp/server

Website: [openlfcp.org](https://openlfcp.org)

The OpenLFCP reference server: an application-agnostic LFCP
synchronization peer in Rust, built on the `lfcp` crate of
[`sdk-rs`](https://github.com/openlfcp/sdk-rs).

The server stores and coordinates LFCP objects according to LFCP Wire. It is
a synchronization peer, not the root of trust: clients verify signatures and
authority themselves. It never understands Markdown, Obsidian, Tasks or
Automerge: it uses the `lfcp` protocol core without the `shared-objects`
feature, and `tests/dependency_policy.rs` fails if Automerge appears in its
dependency tree.

## Scope

The reference server implements the server side of the
OpenLFCP MVP 0.1 subset of LFCP-WIRE-01 at `mvp-0.1-baseline.9`: one
coordinator per Resource, one endpoint, no federation, mirror seeding or
presence. See `.github: docs/release/deferred-wire-01-features.md` (in [openlfcp/.github](https://github.com/openlfcp/.github)). It does
not claim full LFCP-WIRE-01 conformance.

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
- Catch-up, deduplication and restart durability (LFCP-051, 052, 054).
- Docker image and compose (LFCP-055).
- Setup and admin HTTP (LFCP-046): first-run pairing, hosting policy.
- `lfcp-admin` CLI (POST-014): pairing and signed admin calls.
- Abuse limits (POST-003): quota hosting mode by default, client IP behind
  a trusted proxy, per-IP and rate limits, a global storage floor.

## Store

`<state_dir>/server.sqlite3`, one connection owned by one thread behind an
async facade (`store::Store`): operations are serialized and every write is
acknowledged after its transaction commits.

- Permissions: a state directory the server creates is mode 0700. The
  database and its `-wal` and `-shm` files are mode 0600, tightened at
  every start if an older server left them looser. An existing state
  directory keeps its mode. This applies on Unix. On Windows the server
  does not tighten permissions: the state files inherit the state
  directory's ACL, so put the state directory where only the server's
  user can read it (e.g. under that user's profile).

- Durability: WAL journal with `synchronous = FULL`, so a committed write
  survives a crash or power loss (on storage that honors fsync). `tests/process_restart.rs` checks this on the real binary: it kills the
  process with SIGKILL right after the last ACK (and, separately, stops it
  with SIGTERM), and a new process on the same state directory still has
  every acknowledged object, the server ID, the Control Head and consumed
  claims, and the dedup and equivocation indexes. Power loss itself is
  not simulated: the claim holds as far as SQLite and fsync do. That backs
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
- Storage accounting (migration 3, POST-003): `resource_usage` holds each
  Resource's stored bytes, kept by insert triggers in the writing
  transaction and backfilled from an older database when it migrates;
  `quota_overrides` holds the administrator's per-Principal quotas. No
  client IP is stored.
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
| `max_connections` | | `1024` | Open TCP connections, WebSocket included; a connection past it gets HTTP 503 with `Retry-After: 5` and is closed. 1–1000000 |
| `handshake_timeout_ms` | | `10000` | Time allowed for a request's HTTP headers, and for a WebSocket connection to reach READY; 1000–600000 |
| `max_outbound_bytes` | | 4 × `max_message_bytes` | Outbound bytes one WebSocket connection may hold: queued replies, pushes and GET pages being built. At least 2 × `max_message_bytes` |
| `max_total_outbound_bytes` | | `67108864` | Outbound bytes all connections may hold together; at least `max_outbound_bytes` (the default grows to it). GET pages and Snapshots may use 7/8 of it, the rest stays free for control replies |
| `write_timeout_ms` | | `10000` | Time the socket may take to accept one outbound message; a peer that stops reading is then closed and its queue freed. 1000–600000 |
| `admin_body_timeout_ms` | | `10000` | Time allowed for a setup/admin request body; a slower body gets HTTP 408 and its connection is closed. 1000–600000 |
| `log_level` | `--log-level` | `info` | `error`, `warn`, `info`, `debug` or `trace` |
| `trusted_proxies` | | `[]` | Proxies (IPv4/IPv6 CIDRs or addresses) whose `client_ip_header` is believed; see "Abuse limits" |
| `client_ip_header` | | `x-forwarded-for` | The header a trusted proxy puts the client IP in: `x-forwarded-for`, `x-real-ip`, `cf-connecting-ip` or any other |
| `max_connections_per_ip` | | `32` | Open WebSocket connections per client IP; `0` disables |
| `connections_per_ip_per_minute` | | `20` | New WebSocket connections per client IP per minute (burst the same); `0` disables |
| `ws_messages_per_second` | | `50` | LFCP messages per second on one WebSocket connection; `0` disables |
| `ws_message_burst` | | `200` | The burst of `ws_messages_per_second` |
| `admin_requests_per_ip_per_minute` | | `60` | `/setup` and `/admin/*` requests per client IP per minute; `0` disables |
| `max_tracked_ips` | | `65536` | Client IPs tracked at once (bounded memory); 1024–10000000 |
| `quota_resources_per_principal` | | `20` | Quota mode: Resources one hosting Principal may host |
| `quota_bytes_per_principal` | | `268435456` (256 MiB) | Quota mode: stored bytes across one hosting Principal's Resources |
| `quota_bytes_per_resource` | | `134217728` (128 MiB) | Quota mode: stored bytes of one Resource |
| `hosts_per_ip_per_day` | | `10` | Quota mode: new Resources hosted per client IP per 24 hours; `0` disables, at most 10000 |
| `quota_control_reserve_bytes` | | `16777216` (16 MiB) | Quota mode: what Control Records and Key Packages may store past the byte quotas of their Resource and Principal, so revocation and key rotation work at quota |
| `max_total_bytes` | | unset | Every mode: the store's total stored bytes (Control Records and Key Packages exempt); unset is no cap |
| `min_free_bytes` | | `2147483648` (2 GiB) | Every mode: the least free disk space on `state_dir` for bulk writes; Control Records and Key Packages pass until a quarter of it; `0` disables |
| `disk_check_interval_ms` | | `10000` | How long a free disk space reading is reused; 100–3600000 |

`GET /health` answers `{"status":"ok"}` and nothing else.
`lfcp-server --health-check [--config FILE]` probes it for the configured
`bind` address (loopback when `bind` is unspecified) and exits 0 when it
answers 200: a container health check without curl. SIGINT or
SIGTERM stops accepting connections and gives open ones 10 seconds.

The server ID (WIRE-01 §35, §37) is 32 random bytes created on first start
in `<state_dir>/server-id` (mode 0600). It never changes afterwards, is the
same for every connection, and is never derived from the host name or an
address. A corrupt file stops the server instead of being replaced.

## Abuse limits

A server open to unknown clients (POST-003; security review H5, M2, M3)
has these limits, all server infrastructure, never LFCP Resource
authority. Every number is a setting (see "Running"). Refusals use the
WIRE-01 §62 codes, with a diagnostic (§60 field 1, §61 field 1); HTTP
refusals are 429 with `Retry-After` (seconds).

**Client IP.** Behind a reverse proxy every TCP peer is the proxy. The
server believes `client_ip_header` only when the TCP peer is in
`trusted_proxies`, and otherwise uses the peer address, so a client
cannot forge its address. A trusted header is read as a comma-separated
list (every line of it, in order) from the right: the rightmost entry
that is not itself a trusted proxy is the client; if every entry is
trusted, the leftmost. An entry that is not an IP address (`1.2.3.4`,
`1.2.3.4:5678` and `[2001:db8::1]:443` are) makes the server use the peer
address. Per-IP limits group IPv6 clients by their /64. The "websocket
open" log line carries both: `peer=<TCP peer> client=<client IP>`.

What the proxy must do: overwrite (not append) the header with the
address it sees, and be the only way in. nginx:
`proxy_set_header X-Forwarded-For $remote_addr;` (or `X-Real-IP
$remote_addr` with `client_ip_header = "x-real-ip"`), with
`trusted_proxies` set to the address or network nginx reaches the server
from (for a container on a Docker bridge network, that network's subnet
or gateway, from `docker network inspect`). Behind Cloudflare either let
the proxy resolve the client (nginx `real_ip_header CF-Connecting-IP`
with `set_real_ip_from` for Cloudflare's ranges, Caddy's global
`trusted_proxies` with `client_ip_headers CF-Connecting-IP`), or set
`client_ip_header = "cf-connecting-ip"` and make sure only Cloudflare
reaches the proxy. `deploy/` does this for Caddy (see "Docker").

| Limit | Default | Over it |
| --- | --- | --- |
| open WebSockets per client IP (`max_connections_per_ip`) | 32 | the upgrade gets HTTP 429, `Retry-After: 5`, `too many connections from this address` |
| new WebSockets per client IP (`connections_per_ip_per_minute`, token bucket) | 20/min | HTTP 429, `Retry-After` until a token refills, `too many new connections from this address` |
| messages per WebSocket connection (`ws_messages_per_second`, `ws_message_burst`, token bucket) | 50/s, burst 200 | `ERROR(RATE_LIMITED)`, `message rate limit exceeded`, close 1008 |
| admin requests per client IP (`admin_requests_per_ip_per_minute`; `/setup`, `/admin/*`, not `/health`) | 60/min | HTTP 429, `Retry-After`, `{"error": "too many admin requests from this address; retry later"}`, before the body is read |
| quota mode: Resources per hosting Principal (`quota_resources_per_principal`) | 20 | `RESOURCE_HOST`: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: Resources per hosting Principal` |
| quota mode: stored bytes per hosting Principal (`quota_bytes_per_principal`) | 256 MiB | `RESOURCE_HOST` and puts: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: stored bytes per hosting Principal`; control puts only past it plus the reserve |
| quota mode: stored bytes per Resource (`quota_bytes_per_resource`) | 128 MiB | puts: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: stored bytes per Resource`; control puts only past it plus the reserve |
| quota mode: new Resources per client IP per 24 h (`hosts_per_ip_per_day`) | 10 | `RESOURCE_HOST`: `NACK(RATE_LIMITED)`, `rate limited: new Resources per client address per day` |
| every mode: the store's total (`max_total_bytes`) | unset | `RESOURCE_HOST` and bulk puts: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: server storage full` |
| every mode: free disk on `state_dir` (`min_free_bytes`) | 2 GiB | `RESOURCE_HOST` and bulk puts: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: server disk space low` |
| every mode: the hard disk floor, a quarter of `min_free_bytes` | 512 MiB | every put: `NACK(QUOTA_EXCEEDED)`, `quota exceeded: server disk space critically low` |

- "Puts" are `CONTROL_PUT`, `DATA_PUT`, `KEY_PACKAGE_PUT` and
  `SNAPSHOT_PUT`: a write is refused when it would pass a byte limit
  (stored bytes plus the request's objects). Reads (`RESOURCE_OPEN`,
  `*_HAVE`, `*_GET`) keep working.
- Revocation always gets through. "Control puts", `CONTROL_PUT` and
  `KEY_PACKAGE_PUT`, carry what a revocation needs end to end: the
  Capability Revoke, the Key Epoch that rotates the DEK, and the Key
  Packages that deliver it to the remaining readers. They are exempt from
  `max_total_bytes`, pass a low disk until the hard floor, and may store
  `quota_control_reserve_bytes` past the byte quotas, so a writer who
  fills a Resource cannot block their own revocation. "Bulk puts",
  `DATA_PUT` and `SNAPSHOT_PUT`, keep every limit. The reserve is bounded
  rather than unlimited: anyone can own a Resource of their own and
  would otherwise write Control Records without end. A member who may
  write Control Records can still use up the reserve; the administrator
  can then raise the Principal's quota with an override.
- Hosting the same Genesis again is not a new Resource: it passes every
  hosting limit.
- Stored bytes are the exact object bytes (`resource_usage`, kept by
  SQLite triggers in the writing transaction), attributed to the
  Principal that hosted the Resource here, whoever writes. Checks run
  before the write; concurrent writes to different Resources of one
  Principal can pass a Principal quota by at most one request each.
- The free disk space is read at most once per `disk_check_interval_ms`
  (one `statvfs`); a failed reading is logged and refuses nothing.
- The per-IP state is in memory: at most `max_tracked_ips` entries
  (IPv6 per /64). When full, entries with nothing to remember are
  dropped, then the least recently seen ones without an open connection,
  down to 7/8 of the cap; an entry with an open connection is kept, so
  the table is bounded by `max_tracked_ips` plus `max_connections`. A
  restart forgets it (the hosting count per IP included).
- Admin challenges cannot be exhausted (see "Administration").
- `max_connections` (1024, every TCP connection) still applies first.

## Memory

The server's memory is bounded by its configuration, not by the size of
the Resources it serves (security review H6, POST-004). As a rule of
thumb:

```text
RSS ≈ idle (about 6 MiB)
    + SQLite page cache (2 MiB: SQLite defaults, no mmap)
    + max_total_outbound_bytes                    (every queued reply and GET page)
    + max_connections × (3 × max_message_bytes + 256 KiB)  (a message being read and decoded, WebSocket buffers)
```

- The outbound term is a hard bound: replies, GET pages and live pushes
  all hold their bytes in the budgets until they are written.
- The inbound term is a worst case. It needs every connection to be
  receiving a maximum-size message at the same moment (security review
  M5, after READY).

Measured on macOS (arm64, release build). Peak RSS of the server
process, with clients on loopback reading as fast as they can:

| Load | 0.1.0 | Now |
| --- | --- | --- |
| idle | 5 MiB | 5–8 MiB |
| 1 client, `DATA_GET` of a 256 MiB Resource, defaults | 619 MiB | 41 MiB |
| the same, with the small-host settings below | – | 13 MiB |
| 50 clients, each `DATA_GET` of a 16 MiB Resource, defaults | 750 MiB | 41 MiB |
| the same, with the small-host settings below | 117 MiB | 25 MiB |

For a container limited to 128 MB:

```toml
max_message_bytes = 1048576          # 1 MiB: also the largest Snapshot or DATA_PUT clients can send
max_connections = 24
max_outbound_bytes = 4194304         # 4 MiB per connection
max_total_outbound_bytes = 25165824  # 24 MiB in all
```

That gives 6 + 2 + 24 + 24 × 3.25 ≈ 110 MiB in the worst case. With
`max_connections = 32` it is about 136 MiB in the worst case, so only if
the inbound worst case is accepted as unlikely.

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
- Every close the server starts lingers, so the peer still reads the last
  ERROR and close frame. Without it, closing a socket with unread bytes
  sends RST (on Linux), and the peer discards what it had not read yet.
  The server shuts down its write half, then reads and discards the peer's
  bytes until EOF. It stops after at most 2 seconds and `max_message_bytes`
  + 64 KiB, or at shutdown, then drops the socket.
- Other undecodable messages get `ERROR` with their code (malformed CBOR,
  an unknown type → `PROTOCOL_UNSUPPORTED`) and the connection stays open,
  unless sdk-rs says the error closes it.
- Outbound memory is bounded in bytes (security review H6, POST-004).
  Messages are queued encoded, and each holds its size from two budgets
  until it is written: the connection's `max_outbound_bytes` and the
  server-wide `max_total_outbound_bytes` (`src/budget.rs`). Replies wait
  for room, so a large reply is paced by the peer's reading. Waiting
  parks the session: waiters are served in order, each woken once its
  bytes fit. Bulk replies (GET pages, Snapshots) may use 7/8 of the
  server-wide budget, and control replies (the handshake, ACK, NACK,
  PONG, Have vectors) are served ahead of them. So another session's
  handshake gets through while GET pages fill the server. A live push
  that does not fit closes its subscriber (1013), as before. The queue
  also holds at most 256 messages.
- A write that takes longer than `write_timeout_ms` (10 s) ends the
  connection: its queue is dropped and every reserved byte released, and
  a reply waiting for room stops. A peer that stops reading is therefore
  closed after that timeout.
- A message over 64 KiB is sent as WebSocket fragments of 64 KiB (§31
  allows it). tungstenite copies each frame into a write buffer that
  keeps its largest size for the life of the connection, so a whole 8 MiB
  frame left every connection holding 8 MiB or more outside the budgets.
  The peer reassembles the message, and its size limits apply to the
  whole message. sdk-ts (WHATWG WebSocket), the plugin E2E and tungstenite
  clients receive them unchanged.
- A connection that sends no LFCP message for three heartbeats is closed
  (1001). Only LFCP messages count, an LFCP `PING` included; WebSocket
  ping and pong frames do not.
- Before READY the peer is unauthenticated, and the limits are tighter
  (security review M2, M5). The connection must reach READY within
  `handshake_timeout_ms` of opening, else close 1008. An LFCP `PING`
  before READY is answered but does not extend this deadline. At most 16
  messages are read before READY; the 17th gets `ERROR(RATE_LIMITED)` and
  close 1008. A message over 64 KiB gets `ERROR(MESSAGE_TOO_LARGE)` and
  close 1009 without being decoded.
- After READY, a connection may send `ws_messages_per_second` messages
  (burst `ws_message_burst`); the next gets `ERROR(RATE_LIMITED)`
  (`message rate limit exceeded`) and close 1008. A WebSocket upgrade past
  the per-IP connection limits gets HTTP 429 (see "Abuse limits").
- An HTTP request whose headers do not arrive within
  `handshake_timeout_ms` has its connection closed.
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
  owner in its body, ws/wss URLs), the hosting policy is applied (with the
  quotas and the storage floor of "Abuse limits"), the Genesis is
  committed to the store, and only then `RESOURCE_HOSTED`
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
(`session::HostingPolicy`). The server runs the admin-managed policy
(`admin::ManagedHosting`, see "Administration"): quota mode by default, so
any authenticated Principal may host, with or without a credential,
within its quota. Neither a credential nor
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

The coordinator keeps a lock and a cached chain only for hosted
Resources. A request that names an unknown Resource ID costs one store
lookup and leaves nothing in memory.

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
| the storage floor and quotas of "Abuse limits" | `QUOTA_EXCEEDED` with a diagnostic |
| `ingest::IngestPolicy` (a hook for further limits; unlimited by default) | `QUOTA_EXCEEDED`, `RATE_LIMITED` |

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

GET replies are streamed, not built in memory (security review H6,
POST-004). `CONTROL_GET`, `DATA_GET` and `KEY_PACKAGE_GET` read the store
one page at a time (keyset paging in `store::Listing`). Each page is first
sized from the stored object lengths, then room for it is reserved in the
outbound budgets, then it is read and encoded straight into one batch
message (`max_message_bytes` − 1 KiB of objects). The budgets fill up
while the peer reads, so a GET of any size holds at most
`max_outbound_bytes`. The pages are the batches the whole reply would be
cut into, so the replies are unchanged on the wire. An empty result is one
empty batch. `SNAPSHOT_GET` sends one stored Snapshot, at most
`max_message_bytes`.

Before anything is looked up, a `DATA_GET` with more than 256 ranges
(WIRE-01 §49) or a `KEY_PACKAGE_GET` with more than 256 distinct epochs
gets `NACK(MALFORMED_MESSAGE)`. Repeated epochs are looked up once, and
overlapping ranges of one actor are merged, so no unit is read twice.

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
| `serde_json` | The setup/admin HTTP API |
| `rusqlite` (bundled SQLite) | The store |
| `zeroize` (`lfcp-admin` only) | Key bytes and the setup code are wiped after use |
| `fs4` (`sync`; `rustix`, on Windows `windows-sys`) | Free disk space for the storage floor, without `unsafe` here |

97 unique crates (on macOS) in the normal dependency tree. No web framework, no ORM,
no clap.

## Administration

The setup and admin HTTP API (`src/admin.rs`, LFCP-046) shares the
listener and speaks JSON only. It is server infrastructure: it never
touches Resource data and is never LFCP Resource authority. An
administrator gets no Resource ability, and is not even allowed to host
unless the hosting policy allows it. There is no account system and no
REST access to Resources: they are synchronized over the WebSocket only.

### lfcp-admin

`lfcp-admin` (`crates/lfcp-admin`, POST-014) is the administration CLI: it
holds the administrator's LFCP Principal key and signs every proof the API
asks for. Build it with `cargo build --release -p lfcp-admin` and run it
on the administrator's machine. It speaks plain `http://` only and is
meant for the server's loopback port over an SSH tunnel; an `https://`
URL is refused.

```sh
ssh -N -L 17820:127.0.0.1:17820 admin@sync-host &   # the tunnel
export LFCP_ADMIN_KEY=~/.config/lfcp/admin.key       # or --key FILE on every call
lfcp-admin keygen                                    # mode 0600; prints the Principal ID
ssh admin@sync-host sudo cat /var/lib/lfcp/setup-code | lfcp-admin pair --setup-code -
lfcp-admin status
lfcp-admin hosting get
lfcp-admin hosting set quota                         # or open
lfcp-admin hosting set allow_list --principal <id> --credentials-file deploy-keys.txt
lfcp-admin quota list
lfcp-admin quota get <id>
lfcp-admin quota set <id> --resources 50 --bytes 1073741824
lfcp-admin quota set <id> --resources 0 --bytes 0    # stop a Principal's hosting and writes
lfcp-admin quota clear <id>
```

- `--url` defaults to `http://127.0.0.1:17820`; `--key` defaults to
  `$LFCP_ADMIN_KEY`.
- The key file is JSON with the Principal ID and its two secrets. `keygen`
  creates it with mode 0600 and never replaces a file. Every command
  refuses a key that its group or others can read. Keep a backup: losing
  the key leaves no administrator, and a new pairing needs a new state
  directory.
- `pair --setup-code -` reads the code from stdin, so it stays out of
  shell history and `ps`; `--setup-code-file PATH` reads it from a file.
  `--setup-code CODE` works too.
- Hosting credentials are read from a file, one hex credential per line.
- Each command opens its own admin session; tokens are never written to
  disk. Answers print as JSON on stdout. Refusals print the server's
  error and HTTP status on stderr, with exit status 1; usage errors exit
  with 2.
- No secret is printed: not the key, the setup code, credentials or
  tokens.
- The image does not ship `lfcp-admin`. The admin key stays on the
  administrator's machine and never on the server host, and the tunnel
  needs nothing in the container.

### The HTTP API

`lfcp-admin` is a client of this API, and the description is for other
clients.

First run (WIRE-01 §92). While no administrator is paired, each start
creates a one-time pairing code (`XXXX-XXXX`, from the OS random source).
The code is written to `<state_dir>/setup-code`, mode 0600, replacing the
previous one. It never goes to stdout, stderr or the log, because
container runtimes keep those (`docker logs`). The log says only where
the code is:

```text
pairing code written to /var/lib/lfcp/setup-code (expires in 60 minutes; pair an LFCP Principal at /setup/pair)
```

Read it with `cat <state_dir>/setup-code` as the server's user. The pairing
removes the file, and so does a start once an administrator is paired.
The store keeps only its hash. The code expires after an hour (restart
for a new one), is destroyed after 5 wrong attempts, and is destroyed by
the pairing. The log never contains the code, proofs or tokens.

Pairing binds an LFCP Principal to the administrator role, proven with the
Principal's own key; there are no passwords.

1. `POST /admin/challenge` answers `{"challenge": <32 bytes hex>}`,
   valid for 5 minutes (and until a restart). Challenges are stateless
   (POST-003): one is its expiry, a nonce and an HMAC-SHA256 tag under a
   key drawn at start, so issuing one stores nothing, and no flood can
   use them up for the administrator; floods are also bounded by the
   per-IP admin rate limit. A proof that opened a session is remembered
   until its challenge expires, so it cannot be replayed; a refused proof
   leaves nothing behind. The pairing is single use through its code.
2. `POST /setup/pair` with `{"code", "principal", "challenge", "proof"}`:
   - `principal` is the encoded Principal Descriptor, in hex;
   - `proof` is a COSE_Sign1 by that Principal (hex) over the
     deterministic CBOR `["LFCP-ADMIN-v1", "pair", server_id, challenge]`,
     where `server_id` comes from `GET /setup`.
   - The answer is 200, 403 for a wrong code, 410 when there is no code
     or it expired, 401 for a bad proof, 400 for a malformed request.

Later administration:

- `POST /admin/session` with the same proof (purpose `"session"`) returns
  a bearer token, valid 15 minutes and kept only as a hash in memory.
- `GET /admin/status`: server ID, limits, public URLs, durability,
  administrators, number of hosted Resources.
- `GET` and `PUT /admin/hosting`:
  - `{"mode": "quota"}`, the default of a server that never set a policy
    (POST-003; 0.1.0 defaulted to open): any authenticated Principal may
    host within its quota ("Abuse limits");
  - `{"mode": "open"}`: anyone, without quotas;
  - `{"mode": "allow_list", "principals": [<id hex>], "credentials": [<hex>]}`,
    without quotas. Credentials are stored as SHA-256 hashes and only
    counted when read.
  The change takes effect on the next request and persists. The storage
  floor applies in every mode.
- `GET /admin/quotas`: the mode, the configured default quota
  (`{"resources", "bytes", "resource_bytes"}`) and every override.
- `GET /admin/quotas/<principal id hex>`: that Principal's `override`
  (or `null`), its effective `quota`, and its `usage`
  (`{"resources", "bytes"}`: the Resources it hosts and their stored
  bytes).
- `PUT /admin/quotas/<principal id hex>` with any of `{"resources",
  "bytes", "resource_bytes"}` (a missing or `null` field keeps the
  default) sets its override, which persists; `DELETE` removes it. Both
  answer as `GET`.
- `GET /admin/resources`: per Resource, its ID, Control Head sequence,
  object counts and bytes; never contents.

A request body (at most 16 KiB) must arrive within
`admin_body_timeout_ms` (default 10 s). A slower one gets 408 and the
connection is closed, so a trickled body cannot hold a connection place.

`GET /health` stays `{"status":"ok"}`.

`/setup` and `/admin/*` requests count against
`admin_requests_per_ip_per_minute` (default 60) per client IP; past it,
HTTP 429 with `Retry-After`.

## Docker

`deploy/` holds a container setup (LFCP-055): the server image, a Compose
file that puts [Caddy](https://caddyserver.com) in front for TLS (`wss://`,
WIRE-01 §16), and a check script.

On a machine with Docker (Compose v2) and git, starting from nothing:

```sh
mkdir openlfcp && cd openlfcp
git clone https://github.com/openlfcp/server
git clone https://github.com/openlfcp/sdk-rs
git -C sdk-rs checkout "$(jq -r .commit server/sdk-rs.lock)"
cd server
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml cp proxy:/data/caddy/pki/authorities/local/root.crt .
curl --cacert root.crt https://localhost/health
```

- Image (`deploy/Dockerfile`): a multi-stage build. A `rust` image runs
  `cargo build --release --locked`; the runtime is distroless
  `cc-debian12:nonroot` (glibc, no shell or package manager), running as
  uid 65532. The build context is the parent of `server/` and `sdk-rs/`,
  and `Dockerfile.dockerignore` lets in only their Rust sources.
- State: the `lfcp-state` volume at `/var/lib/lfcp` (server ID and SQLite
  database). Recreating the containers keeps it; `down -v` destroys it,
  which gives a new server.
- Health: the image's `HEALTHCHECK` runs `lfcp-server --health-check`
  against `/health`. The proxy starts once the server is healthy.
- Configuration: `deploy/server.toml`, mounted read-only. Set
  `public_urls` to the `wss://` URL clients use, so the server coordinates
  the Resources that name it, and consider `max_total_bytes`.
- Client IP: the compose network has a fixed subnet (`172.30.78.0/24`)
  and the proxy a fixed address (`172.30.78.10`), the only
  `trusted_proxies` entry of `server.toml`. The Caddyfile replaces any
  client-sent `X-Forwarded-For` with `{client_ip}`, the address Caddy
  sees. If the subnet is taken on the host, change it, the proxy's
  address and `trusted_proxies` together. Behind Cloudflare, give Caddy a
  global `servers { trusted_proxies static <Cloudflare ranges>
  client_ip_headers CF-Connecting-IP }` so `{client_ip}` is the real
  client.
- Endpoints: `https://<host>/health` and `wss://<host>/v1/ws` through the
  proxy. The server's own port is not published.
- TLS: by default (`LFCP_TLS=internal`) Caddy issues certificates from its
  local CA, for development; clients must trust
  `/data/caddy/pki/authorities/local/root.crt` from the proxy. For
  production, set `LFCP_SITE` to the host name and `LFCP_TLS` to an email
  address (a Let's Encrypt certificate, with ports 80 and 443 reachable),
  or to the paths of your own certificate and key mounted into the proxy.
  `LFCP_HTTPS_PORT` and `LFCP_HTTP_PORT` change the published ports.
- No credentials are baked in or committed. At first start the server
  writes a one-time admin pairing code to `/var/lib/lfcp/setup-code` in
  the state volume (mode 0600), never to `docker logs`. The image has no
  shell; read the code with `docker compose -f deploy/compose.yaml cp
  lfcp-server:/var/lib/lfcp/setup-code - | tar -xO`. `lfcp-admin`
  speaks plain http to the server's own port, which this Compose file
  does not publish. Publish it on the host's loopback only (`ports:
  ["127.0.0.1:17820:7820"]` on `lfcp-server`, as `compose.check.yaml`
  does), then pair over an SSH tunnel to that port:
  `docker compose -f deploy/compose.yaml cp lfcp-server:/var/lib/lfcp/setup-code - | tar -xO | lfcp-admin pair --setup-code -`
  (see "Administration"). Recreating the containers on the same volume
  keeps the pairing; a new volume is a new server with a new code.

`deploy/check.sh` builds the image and checks it end to end. It verifies:
- the user is non-root and the container is healthy;
- `/health` and a WebSocket upgrade selecting `lfcp-1` work through the
  proxy;
- a Resource populated over the protocol (as in
  `tests/process_restart.rs`) survives recreating the containers on the
  same volume;
- after `down -v` the server is new and the Resource is gone;
- the server logs the proxy as the peer and a client address that is not
  the proxy, and ignores a forged `X-Forwarded-For`.

CI runs it in the `docker` job.

Prebuilt images are published to `ghcr.io/openlfcp/lfcp-server` for
`linux/amd64` and `linux/arm64` by `.github/workflows/image.yml`: a pushed
`v*` tag publishes the version (`v0.1.0` → `0.1.0`) and `latest`, and a
manual run publishes a chosen tag. Each architecture is built natively,
with sdk-rs at the commit in `sdk-rs.lock`, and must turn healthy before
anything is tagged. A host that cannot build Rust pulls the image instead
and mounts its own `server.toml`; pin a version, not `latest`.

## sdk-rs and the spec

sdk-rs is consumed from a sibling checkout, `../sdk-rs`, as a path
dependency. `sdk-rs.lock` records the commit the server is built against;
`tests/sdk_rs_lock.rs` fails when the checkout is at another commit and
warns when the `lfcp` crate has uncommitted changes. Move the lock
deliberately when the server needs newer sdk-rs code. A git or tag
dependency replaces this at a release milestone.

`spec.lock` pins `openlfcp/spec` (`mvp-0.2-baseline.1`: `mvp-0.1-baseline.9`
unchanged, plus shared sections, which the server does not read); tests read vectors
from `../spec` (or `$LFCP_SPEC_DIR`) with `git show` at the locked commit.

## Build from a clean checkout

With `sdk-rs` and `spec` checked out next to this repository:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The tests in `tests/process_restart.rs` start the `lfcp-server` binary. A
test that panics or returns stops its server and removes the server's
temporary files. A test process that is itself killed (SIGKILL, a CI
timeout, Ctrl-C) takes its servers with it too: a watchdog `sh` started
with each server sees its stdin pipe close, then kills the server and
removes the files. The server has no test-only flag for this.

## Follow-ups

- Optional built-in TLS (a `rustls` feature) for a single-binary
  deployment without a reverse proxy.

## License

Apache License 2.0. See [LICENSE](LICENSE).
