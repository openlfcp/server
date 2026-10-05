//! The restart check through Docker Compose (LFCP-055), one phase per run,
//! driven by `deploy/check.sh`; ignored by a plain `cargo test`.
//!
//! - `LFCP_E2E_ADDR`: the server's WebSocket address (`host:port`).
//! - `LFCP_E2E_PHASE`: `populate` (host the published Resource and put
//!   everything), `verify` (after the containers were recreated on the same
//!   volume: everything is still there), or `fresh` (after the volume was
//!   destroyed: a new server ID and no Resource).
//! - `LFCP_E2E_STATE`: a file carrying the server ID and the randomized Key
//!   Package from `populate` to the later phases.

mod support;

use std::net::SocketAddr;

use lfcp::wire::message::Body;
use support::durability::{populate, second_package, session, verify_after_restart};
use support::vectors::Vectors;

const RESOURCE_NOT_HOSTED: u64 = 6;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; run deploy/check.sh"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running container; run deploy/check.sh"]
async fn container_phase() {
    let v = Vectors::load();
    let addr: SocketAddr = env("LFCP_E2E_ADDR").parse().unwrap();
    let state = std::path::PathBuf::from(env("LFCP_E2E_STATE"));
    match env("LFCP_E2E_PHASE").as_str() {
        "populate" => {
            let second = second_package(&v);
            let server_id = populate(&v, addr, &second).await;
            std::fs::write(
                &state,
                format!(
                    "{}\n{}\n",
                    lfcp::base::to_hex(&server_id),
                    lfcp::base::to_hex(&second)
                ),
            )
            .unwrap();
        }
        phase @ ("verify" | "fresh") => {
            let text = std::fs::read_to_string(&state).unwrap();
            let mut lines = text.lines();
            let server_id: [u8; 32] = lfcp::base::from_hex(lines.next().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let second = lfcp::base::from_hex(lines.next().unwrap()).unwrap();
            if phase == "verify" {
                verify_after_restart(&v, addr, server_id, &second).await;
            } else {
                let (mut client, id) = session(addr, &v.principal("bob")).await;
                assert_ne!(id, server_id, "a destroyed volume is a new server");
                client
                    .request(Body::ResourceOpen {
                        resource_id: v.resource(),
                        control_heads: vec![],
                        have: vec![],
                        grant_ids: None,
                        flags: Some(0),
                    })
                    .await;
                match client.recv().await.body {
                    Body::Nack(e) => assert_eq!(e.code, RESOURCE_NOT_HOSTED),
                    other => panic!("expected NACK, got {other:?}"),
                }
            }
        }
        other => panic!("unknown phase {other}"),
    }
}
