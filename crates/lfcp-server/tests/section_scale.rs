//! Storage and transfer of a long-typed section (LFCP-02-067, its server
//! side): a writer types into one paragraph of a shared section, its
//! changes coalesced k characters to a change, one Data Unit each, built
//! with sdk-rs at sdk-rs.lock. The server stores them byte for byte; this
//! measures what the Resource's quota counts, what the database files
//! grow by, and the time of DATA_PUT (one unit per message, as live typing
//! sends them, and 64 per message, as a catch-up does) and of DATA_GET of
//! the whole history.
//!
//! A measurement, not a check: ignored by default, run with
//!
//! ```text
//! cargo test --release -p lfcp-server --test section_scale -- --ignored --nocapture
//! ```
//!
//! The message rate limit is raised so the server's own cost is measured,
//! not the limiter's (the default, 50 messages per second with a burst of
//! 200, is far above live typing).

mod support;

use std::time::Instant;

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{AutoCommit, ObjId, ReadDoc, ROOT};
use lfcp::base::ResourceId;
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, SectionsDoc};
use lfcp_server::limits::AbuseLimits;
use support::lfcp::{start, state_dir, Client, Options};
use support::sections::{
    alice, genesis, get_all, head, host, put_all, seal_all, SECTION, SECTIONS,
};

const PARAGRAPH: &str = "019a2f85-7b31-7c42-8003-000000000001";
const PLACEMENT: &str = "019a2f85-7b31-7c42-8004-000000000001";

/// Prose-like text from a fixed word stream (as the sdk-rs example does).
fn typed(n: usize) -> String {
    const WORDS: &[&str] = &[
        "the",
        "launch",
        "plan",
        "needs",
        "a",
        "review",
        "of",
        "budget",
        "and",
        "timeline",
        "before",
        "we",
        "commit",
        "to",
        "vendor",
        "contract",
        "draft",
        "is",
        "ready",
        "for",
        "legal",
        "team",
        "should",
        "check",
        "pricing",
        "risks",
        "open",
        "questions",
        "remain",
        "about",
        "hosting",
        "support",
        "migration",
        "data",
        "export",
        "schedule",
        "next",
    ];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut out = String::with_capacity(n + 16);
    while out.len() < n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push_str(WORDS[(state % WORDS.len() as u64) as usize]);
        out.push(if state.is_multiple_of(11) { '.' } else { ' ' });
    }
    out.truncate(n);
    out
}

/// The framed plaintexts of a section with one paragraph into which
/// `chars` characters are typed, `k` to a change.
fn typing(resource: ResourceId, chars: usize, k: usize) -> Vec<Vec<u8>> {
    let owner = *alice().descriptor().id();
    let actor = shared_sections::actor_id(&resource, &owner);
    let (mut section, first) =
        SectionsDoc::create(actor.clone(), SECTION, "Long typing", &owner).unwrap();
    let para = section
        .create_node(
            PARAGRAPH,
            NewNode::Paragraph { text: "" },
            SECTION,
            None,
            PLACEMENT,
            &owner,
        )
        .unwrap();
    let mut plaintexts = vec![
        framing::encode_change(first.raw_bytes()),
        framing::encode_change(para.raw_bytes()),
    ];
    let mut doc = AutoCommit::load(&section.save()).unwrap().with_actor(actor);
    let text: ObjId = {
        let (_, nodes) = doc.get(ROOT, "nodes").unwrap().unwrap();
        let (_, map) = doc.get(&nodes, PARAGRAPH).unwrap().unwrap();
        doc.get(&map, "text").unwrap().unwrap().1
    };
    let keys = typed(chars);
    let mut at = 0;
    for chunk in keys.as_bytes().chunks(k) {
        let s = std::str::from_utf8(chunk).unwrap();
        doc.splice_text(&text, at, 0, s).unwrap();
        at += s.len();
        let hash = doc
            .commit_with(
                CommitOptions::default()
                    .with_message("text.edit")
                    .with_time(0),
            )
            .unwrap();
        plaintexts.push(framing::encode_change(
            doc.get_change_by_hash(&hash).unwrap().raw_bytes(),
        ));
    }
    plaintexts
}

fn files_bytes(dir: &std::path::Path) -> u64 {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("server.sqlite3")
        })
        .map(|e| e.metadata().unwrap().len())
        .sum()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "a measurement (LFCP-02-067): run with --ignored --nocapture"]
async fn a_long_typed_section_is_stored_and_served() {
    let owner = alice();
    let owner_id = *owner.descriptor().id();
    let dir = state_dir("section-scale");
    let server = start(
        &dir,
        Options {
            abuse: Some(AbuseLimits {
                ws_messages_per_second: 1_000_000,
                ws_message_burst: 1_000_000,
                min_free_bytes: 0,
                ..AbuseLimits::default()
            }),
            ..Options::default()
        },
    )
    .await;
    println!(
        "{:>8} {:>6} {:>7} {:>11} {:>11} {:>11} {:>12} {:>12} {:>10}",
        "chars",
        "k",
        "units",
        "unit bytes",
        "quota bytes",
        "file bytes",
        "put 1 µs/u",
        "put 64 µs/u",
        "get ms"
    );
    let mut rows = vec![];
    let cases: &[(usize, usize)] = &[(10_000, 1), (50_000, 16), (50_000, 128), (50_000, 1024)];
    for (i, &(chars, k)) in cases.iter().enumerate() {
        // Two Resources per case: one filled a unit per message, one 64.
        let mut timings = vec![];
        let mut stored = (0u64, 0u64, 0u64);
        for (j, per_put) in [1usize, 64].into_iter().enumerate() {
            let resource = ResourceId::from_bytes([0x60 + (2 * i + j) as u8; 32]);
            let g = genesis(&owner, resource, SECTIONS);
            let units = seal_all(&owner, resource, head(&g), &typing(resource, chars, k));
            let unit_bytes: u64 = units.iter().map(|u| u.len() as u64).sum();
            let mut client = Client::connect(server.addr).await;
            client.handshake(&owner).await;
            host(&mut client, g).await;
            let before = files_bytes(&dir);
            let t = Instant::now();
            put_all(&mut client, resource, &units, per_put).await;
            timings.push(t.elapsed().as_secs_f64() * 1e6 / units.len() as f64);
            if per_put == 64 {
                let usage = server.store.usage(resource).await.unwrap().unwrap();
                let t = Instant::now();
                let back = get_all(&mut client, resource, owner_id, units.len() as u64).await;
                let get_ms = t.elapsed().as_secs_f64() * 1e3;
                assert_eq!(back.len(), units.len());
                stored = (
                    unit_bytes,
                    usage.resource_bytes,
                    files_bytes(&dir).saturating_sub(before),
                );
                timings.push(get_ms);
                rows.push((chars, k, units.len(), stored, timings.clone()));
            }
        }
        let (unit_bytes, quota, file) = stored;
        println!(
            "{:>8} {:>6} {:>7} {:>11} {:>11} {:>11} {:>12.0} {:>12.0} {:>10.0}",
            chars,
            k,
            rows.last().unwrap().2,
            unit_bytes,
            quota,
            file,
            timings[0],
            timings[1],
            timings[2]
        );
    }
    println!(
        "{}",
        serde_json::json!({
            "part": "server",
            "rows": rows.iter().map(|(chars, k, units, (unit_bytes, quota, file), t)| serde_json::json!({
                "chars": chars, "per_change": k, "units": units, "unit_bytes": unit_bytes,
                "quota_bytes": quota, "file_bytes_delta": file, "put1_us_per_unit": t[0],
                "put64_us_per_unit": t[1], "get_all_ms": t[2],
            })).collect::<Vec<_>>(),
        })
    );
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
