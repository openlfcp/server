# Server evidence for shared sections (LFCP-02-003)

**Date:** 2026-10-08. **Build:** server 0.3.0 (09c9132) on sdk-rs 259a688,
LFCP-WIRE-01 at `mvp-0.1-baseline.9`. **Method:** reading the code and
the tests named below, and arithmetic on the measured change sizes of
SHARED-SECTIONS-PROFILE-01 §16.3 (`spec` d605f39). No live run.

This records which server facts the SDK and the Obsidian status UI may
present as true for shared sections (MVP 0.2), and where evidence is
missing.

## 1. Acknowledgement and durability

| Fact | Evidence |
| --- | --- |
| A put is acknowledged only after its transaction has committed | `src/store.rs` (header): one SQLite connection on its own thread, each operation in its own transaction; `src/session.rs` sends `ACK` after `put_data_units` returns |
| Committed means durable on the machine | WAL journal with `synchronous = FULL` (`src/store.rs` header and `open_connection`); `DURABILITY = 2`, "durable local persistence" (WIRE-01 §37) |
| The ACK says so | `ACK` carries the request type, every object ID of the put and `durable: true` (`src/session.rs`, `ack`) |
| A killed server keeps every acknowledged object | `tests/process_restart.rs`, `a_killed_server_keeps_every_acknowledged_object` |
| A repeated put is answered as the first one | identical bytes are stored with `INSERT OR IGNORE` and acknowledged again (`src/store.rs`, `put_data_units`); a lost ACK is recovered by sending the same bytes (WIRE-01 §70) |
| A `DATA_PUT` is all-or-nothing | one refused unit refuses the message, nothing stored (`src/session.rs`, WIRE-01 §51) |
| An acknowledged object can still be lost by a restore of an older store | WIRE-01 §37 since baseline.9; clients re-supply it (§68.1); server 0.3.0 refuses a unit whose `previous` it lost (`UNKNOWN_PREVIOUS`, §51.1) |

So the UI may say "accepted by the server" (durable on that server) for an
acknowledged object. It may not say "everyone has it": an ACK says nothing
about other replicas (WIRE-01 §59). The SDK facts recorded in the backlog
stand: the ACK is durable at level 2, sdk-ts emits an `ack` event, and an
outbound item ID is the hash of its Data Unit ID. What remains for the SDK
(LFCP-02-025, LFCP-02-026) is mapping an import or a typing session's
changes to their Data Units and persisting that mapping.

## 2. Profile independence

- The server never reads a Resource's Data Profile. It selects only the
  wire profile in `HELLO` (`src/session.rs`, `select_wire_profile`) and
  sends no application Data Profiles.
- Data Units, Key Packages and Snapshots are validated as LFCP objects only:
  signature, authority at the referenced head, epoch and cutoff, and the
  `previous` link (`src/ingest.rs`, `src/session.rs`). Ciphertexts stay
  opaque.
- There is no profile allowlist. A `org.openlfcp.shared-sections.v1`
  Resource is hosted and synchronized like a Shared Objects one; no server
  change is needed for sections.

## 3. Limits that touch sections

Defaults of server 0.2.0 and later (`README.md`, "Abuse limits"; `src/config.rs`).

| Limit | Default | Effect on sections |
| --- | --- | --- |
| Maximum LFCP message (`max_message_bytes`) | 8 MiB | A `DATA_PUT` of a whole import fits (§4) |
| Messages per connection | 50/s, burst 200 | Units are batched in `DATA_PUT`; an import is a few messages |
| Stored bytes per Resource (quota mode) | 128 MiB | Far above a 200-Task section; long Text history counts |
| Stored bytes per hosting Principal | 256 MiB | Shared by all sections the Principal hosts |
| Resources per hosting Principal | 20 | **One Resource per section (ADR 0009, P1): a 21st hosted section is refused** (`QUOTA_EXCEEDED`) |
| New Resources per client IP per day | 10 | **An 11th section created in a day from one address is refused** (`RATE_LIMITED`) |

The last two rows conflict with one Resource per section. Raising the
defaults on sync.openlfcp.org (`lfcp-admin quota set`, no code change) or
stating the limit is decided by the project owner before the beta (ADR
0009, "Open items"). A refusal reaches the user with its diagnostic; the
plugin already shows `QUOTA_EXCEEDED` and `RATE_LIMITED` messages.

## 4. Sizes of a section import

From the measured change sizes of SHARED-SECTIONS-PROFILE-01 §16.3
(Automerge 3.5.0). A Data Unit adds to its change the CBOR framing
`[1, bstr]` (up to 7 bytes), the 16-byte AEAD tag, the payload fields
(Resource, actor, `previous`, Control Head: 4 × 32 bytes, epoch and
sequence) and the COSE signature structure: under 300 bytes in all.

| Change | Change bytes | Data Unit, about |
| --- | --- | --- |
| 1 Task node | 1,006 | 1.3 KB |
| 100 Task nodes | 88,330 | 88.6 KB |
| 200 Tasks and 200 paragraphs, 2,109 characters | 294,651 | 295 KB |
| At the budgets: 128 Tasks, 128 paragraphs, 8,192 characters | 195,996 | 196 KB |
| At the budgets: 255 Tasks, 1 paragraph, 8,192 characters | 233,856 | 234 KB |

An import of 200 Tasks with a paragraph of about 200 characters each
(40,000 characters) takes at least five changes (§16.3): about 1.2 MB of
Data Units, which fit one `DATA_PUT` well under 8 MiB. About 35 changes at
the budgets fit one message. Message size is therefore not a constraint on
imports; the authoring budgets of §16.2 are.

## 5. Gaps

- No live measurement of a section import against server 0.3.0 was made;
  the sizes above are arithmetic on measured change bytes. A live probe
  belongs to the scale work (LFCP-02-067).
- The per-Resource and per-Principal byte quotas count retained Text
  history; a long-lived section's history is not measured yet
  (SHARED-SECTIONS-PROFILE-01 §16, LFCP-02-067).
- No server defect was found for sections.
