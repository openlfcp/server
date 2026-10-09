# Server fuzz targets

cargo-fuzz (libFuzzer) targets for the reference server, without network
I/O. The crate is not a member of the server's workspace: normal builds and
CI never compile it. It needs a nightly toolchain, `cargo-fuzz`, and the
sdk-rs checkout next to this repository (as the server itself does).

| Target | Input | Checks beyond "no panic" (any panic aborts, the store thread and the server's tasks included) |
| --- | --- | --- |
| `wire_decode` | `[flags][bytes]`: an inbound frame (flag bit 0: text) | `Message::decode_frame` with the server's size limit; a decoded binary message encodes back to its bytes and decodes to itself |
| `session` | `[flags][records]`, each `[kind][len u16 LE][bytes]`: frames after an optional HELLO/AUTH (flag bit 0) and RESOURCE_HOST (bit 1) | the server's own `ws::serve` and `Lfcp` session on an in-memory duplex pipe (hyper's HTTP/1 upgrade as `server::route` does it), on a fresh store; every server message decodes; a request refused with NACK or ERROR (ACTOR_EQUIVOCATION excepted) leaves every table unchanged; the store reopens afterwards |
| `store_open` | `[flags][db len u32 LE][db][wal]` (flag bit 0: write the WAL) | `Store::open` on a corrupted or truncated database returns an error or a store; an opened store answers every read with a value or an error |

## Running

```sh
cd fuzz
# Seeds: a full owner session, then the store it leaves.
LFCP_FUZZ_WRITE_SEEDS=corpus/session cargo +nightly fuzz run session -- -runs=1
cargo +nightly fuzz run session corpus/session -- \
  -rss_limit_mb=2048 -malloc_limit_mb=1024 -timeout=30 -fork=3 -ignore_crashes=1
```

`LFCP_FUZZ_TRACE=1` prints each request of a `session` run and the server's
answer; `LFCP_FUZZ_KEEP_STORE=<dir>` keeps the database a run leaves (the
`store_open` seeds start from one). Runs use fresh directories under
`/dev/shm` when it exists.

The bundled SQLite is C code, which these builds do not instrument (that
needs clang and `-fsanitize=fuzzer-no-link` in `CFLAGS`): `store_open` finds
what the Rust side does with a corrupted file, but its mutations are not
guided inside SQLite.

## Findings

| ID | Finding | Reproducer |
| --- | --- | --- |
| S1 | A database whose ID column holds a blob of another length (a corrupted file: the schema's `CHECK (length(...) = 32)` runs only on insert) makes `id32` panic (`store.rs:207`, `expect("the schema checks 32-byte IDs")`) on the store thread at the first read of the row; every later call of the store is `StoreError::Closed` until a restart, which reads the row again | `repro/S1-store-open` (`store_open` input): `Store::open` succeeds, `control_records` panics the store thread (`store.rs:468`, `469`) |
