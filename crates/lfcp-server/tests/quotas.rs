//! The quota hosting mode, the default of a fresh server (POST-003;
//! security review H5): Resources and stored bytes per hosting Principal,
//! stored bytes per Resource, new Resources per client IP, and the
//! storage floor of every mode, each crossed for its documented refusal,
//! and the administrator's view and overrides.

mod support;

use lfcp::base::{Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{ControlBody, Endpoint, GenesisBody};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use lfcp::wire::message::{Body, ErrorBody};
use lfcp_server::limits::{refusal, AbuseLimits};
use lfcp_server::store::Hosting;
use serde_json::json;
use support::admin::{admin_token, http};
use support::lfcp::{start, state_dir, Client, Options, Running};
use support::vectors::Vectors;

const QUOTA_EXCEEDED: u64 = 18;

const CHAIN: [&str; 11] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
    "C7_grant_carol_delegator",
    "C8_grant_owner_delegated",
    "C9_grant_invite_grandchild",
    "C10_revoke_grandchild",
];

/// `abuse`, without the free disk check (the machine's free space is not
/// the test's).
fn with(abuse: AbuseLimits) -> Options {
    Options {
        abuse: Some(AbuseLimits {
            min_free_bytes: 0,
            ..abuse
        }),
        ..Options::default()
    }
}

/// A Genesis of `resource` owned by `owner`.
fn genesis(owner: &PrincipalKeys, resource: ResourceId) -> Vec<u8> {
    let url = "wss://sync.example.test/v1/ws".to_owned();
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 0,
            previous: None,
            issuer: *owner.descriptor().id(),
        },
        ControlBody::Genesis(GenesisBody {
            data_profile: "org.lfcp.test.raw.v1".into(),
            owner: owner.descriptor().clone(),
            dek_commitment: Hash32::from_bytes([3; 32]),
            endpoints: vec![Endpoint {
                url: url.clone(),
                priority: 0,
                flags: None,
            }],
            coordinator: url,
        }),
        owner,
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

async fn client(server: &Running, keys: &PrincipalKeys) -> Client {
    let mut client = Client::connect(server.addr).await;
    client.handshake(keys).await;
    client
}

async fn host(client: &mut Client, genesis: Vec<u8>) -> Body {
    client
        .request(Body::ResourceHost {
            genesis,
            hosting_credential: None,
        })
        .await;
    client.recv().await.body
}

/// The NACK `QUOTA_EXCEEDED` with `diagnostic`.
fn quota_exceeded(diagnostic: &str) -> Body {
    Body::Nack(ErrorBody {
        code: QUOTA_EXCEEDED,
        diagnostic: Some(diagnostic.into()),
        details: None,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_server_caps_the_resources_of_each_principal() {
    let dir = state_dir("quota-resources");
    let server = start(
        &dir,
        with(AbuseLimits {
            quota_resources_per_principal: 2,
            hosts_per_ip_per_day: 0,
            ..AbuseLimits::default()
        }),
    )
    .await;
    let alice = PrincipalKeys::from_secrets(&[1; 32], [2; 32]);
    let other = PrincipalKeys::from_secrets(&[5; 32], [6; 32]);
    let r = |i: u8| ResourceId::from_bytes([i; 32]);
    let mut a = client(&server, &alice).await;
    for i in 1..=2 {
        assert!(matches!(
            host(&mut a, genesis(&alice, r(i))).await,
            Body::ResourceHosted { .. }
        ));
    }
    assert_eq!(
        host(&mut a, genesis(&alice, r(3))).await,
        quota_exceeded(refusal::RESOURCES)
    );
    // Hosting an already hosted Resource again is not a new one.
    assert!(matches!(
        host(&mut a, genesis(&alice, r(1))).await,
        Body::ResourceHosted { .. }
    ));
    // Another Principal has its own quota.
    let mut o = client(&server, &other).await;
    assert!(matches!(
        host(&mut o, genesis(&other, r(4))).await,
        Body::ResourceHosted { .. }
    ));

    // The administrator sees the mode and the usage, and raises the quota.
    let admin = admin_token(&server, &PrincipalKeys::from_secrets(&[9; 32], [9; 32])).await;
    let (status, body) = http(server.addr, "GET", "/admin/hosting", Some(&admin), None).await;
    assert_eq!((status, body), (200, json!({ "mode": "quota" })));
    let path = format!("/admin/quotas/{}", alice.descriptor().id().to_hex());
    let (status, body) = http(server.addr, "GET", &path, Some(&admin), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["override"], json!(null));
    assert_eq!(body["quota"]["resources"], json!(2));
    assert_eq!(body["usage"]["resources"], json!(2));
    let (status, body) = http(
        server.addr,
        "PUT",
        &path,
        Some(&admin),
        Some(json!({ "resources": 3 })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["override"],
        json!({ "resources": 3, "bytes": null, "resource_bytes": null })
    );
    assert_eq!(body["quota"]["resources"], json!(3));
    assert!(matches!(
        host(&mut a, genesis(&alice, r(3))).await,
        Body::ResourceHosted { .. }
    ));
    let (_, body) = http(server.addr, "GET", "/admin/quotas", Some(&admin), None).await;
    assert_eq!(body["mode"], json!("quota"));
    assert_eq!(body["defaults"]["resources"], json!(2));
    assert_eq!(
        body["overrides"][0]["principal"],
        json!(alice.descriptor().id().to_hex())
    );
    server.stop().await;

    // The override persists; removing it restores the default.
    let server = start(
        &dir,
        with(AbuseLimits {
            quota_resources_per_principal: 2,
            hosts_per_ip_per_day: 0,
            ..AbuseLimits::default()
        }),
    )
    .await;
    let mut a = client(&server, &alice).await;
    assert_eq!(
        host(&mut a, genesis(&alice, r(5))).await,
        quota_exceeded(refusal::RESOURCES),
        "3 of 3"
    );
    let token = {
        // Paired already: a new session.
        support::admin::session_token(&server, &PrincipalKeys::from_secrets(&[9; 32], [9; 32]))
            .await
    };
    let (status, body) = http(server.addr, "DELETE", &path, Some(&token), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["override"], json!(null));
    assert_eq!(body["quota"]["resources"], json!(2));
    // Bad requests.
    for (method, path, body) in [
        ("GET", "/admin/quotas/zz".to_owned(), None),
        ("PUT", path.clone(), Some(json!({ "resources": -1 }))),
        ("PUT", path.clone(), Some(json!({ "files": 1 }))),
    ] {
        assert_eq!(
            http(server.addr, method, &path, Some(&token), body).await.0,
            400,
            "{method} {path}"
        );
    }
    assert_eq!(http(server.addr, "GET", &path, None, None).await.0, 401);
    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A server whose store holds the published chain, hosted by OWNER.
async fn chain_server(
    v: &Vectors,
    name: &str,
    abuse: AbuseLimits,
) -> (Running, std::path::PathBuf) {
    let dir = state_dir(name);
    let server = start(&dir, with(abuse)).await;
    server
        .store
        .host_resource(
            v.cose(CHAIN[0]),
            Hosting {
                host: *v.principal("owner").descriptor().id(),
                durability: 2,
            },
        )
        .await
        .unwrap();
    for i in 1..CHAIN.len() {
        server
            .store
            .commit_control_record(v.cose(CHAIN[i]), v.record_id(CHAIN[i - 1]))
            .await
            .unwrap();
    }
    (server, dir)
}

fn chain_bytes(v: &Vectors) -> u64 {
    CHAIN.iter().map(|c| v.cose(c).len() as u64).sum()
}

async fn put_d1(server: &Running, v: &Vectors) -> Body {
    let mut bob = client(server, &v.principal("bob")).await;
    bob.request(Body::DataPut {
        resource_id: v.resource(),
        units: vec![v.cose("D1_bob_epoch0_seq1")],
    })
    .await;
    bob.recv().await.body
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_past_the_resource_bytes_are_refused() {
    let v = Vectors::load();
    let d1 = v.cose("D1_bob_epoch0_seq1").len() as u64;
    let (server, dir) = chain_server(
        &v,
        "quota-resource-bytes",
        AbuseLimits {
            quota_bytes_per_resource: chain_bytes(&v) + d1 - 1,
            ..AbuseLimits::default()
        },
    )
    .await;
    // A member's write counts against the Resource it writes to.
    assert_eq!(
        put_d1(&server, &v).await,
        quota_exceeded(refusal::RESOURCE_BYTES)
    );
    assert_eq!(
        server.store.total_bytes().await.unwrap(),
        chain_bytes(&v),
        "nothing stored"
    );

    // The administrator lifts it for OWNER's Resources.
    let admin = admin_token(&server, &PrincipalKeys::from_secrets(&[9; 32], [9; 32])).await;
    let path = format!(
        "/admin/quotas/{}",
        v.principal("owner").descriptor().id().to_hex()
    );
    let (status, body) = http(
        server.addr,
        "PUT",
        &path,
        Some(&admin),
        Some(json!({ "resource_bytes": 1u64 << 30 })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["usage"]["bytes"], json!(chain_bytes(&v)));
    assert!(matches!(put_d1(&server, &v).await, Body::Ack(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_past_the_principal_bytes_are_refused_until_open_mode() {
    let v = Vectors::load();
    let d1 = v.cose("D1_bob_epoch0_seq1").len() as u64;
    let (server, dir) = chain_server(
        &v,
        "quota-principal-bytes",
        AbuseLimits {
            quota_bytes_per_principal: chain_bytes(&v) + d1 - 1,
            hosts_per_ip_per_day: 0,
            ..AbuseLimits::default()
        },
    )
    .await;
    assert_eq!(
        put_d1(&server, &v).await,
        quota_exceeded(refusal::PRINCIPAL_BYTES)
    );
    // OWNER cannot host another Resource either: its bytes are spent.
    let mut owner = client(&server, &v.principal("owner")).await;
    let other = genesis(&v.principal("owner"), ResourceId::from_bytes([7; 32]));
    let refused = host(&mut owner, other.clone()).await;
    assert_eq!(refused, quota_exceeded(refusal::PRINCIPAL_BYTES));

    // Open mode has no quotas.
    let admin = admin_token(&server, &PrincipalKeys::from_secrets(&[9; 32], [9; 32])).await;
    let (status, _) = http(
        server.addr,
        "PUT",
        "/admin/hosting",
        Some(&admin),
        Some(json!({ "mode": "open" })),
    )
    .await;
    assert_eq!(status, 200);
    assert!(matches!(put_d1(&server, &v).await, Body::Ack(_)));
    assert!(matches!(
        host(&mut owner, other).await,
        Body::ResourceHosted { .. }
    ));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn new_resources_per_client_ip_are_rate_limited() {
    let dir = state_dir("quota-hosts-per-ip");
    let server = start(
        &dir,
        with(AbuseLimits {
            hosts_per_ip_per_day: 2,
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..AbuseLimits::default()
        }),
    )
    .await;
    let r = |i: u8| ResourceId::from_bytes([i; 32]);
    // Fresh keypairs from one client address: the third is refused.
    for i in 1..=2u8 {
        let keys = PrincipalKeys::from_secrets(&[i; 32], [i; 32]);
        let mut c = proxied(&server, "203.0.113.1", &keys).await;
        assert!(matches!(
            host(&mut c, genesis(&keys, r(i))).await,
            Body::ResourceHosted { .. }
        ));
        // Hosting it again is not new and does not count.
        assert!(matches!(
            host(&mut c, genesis(&keys, r(i))).await,
            Body::ResourceHosted { .. }
        ));
    }
    let keys = PrincipalKeys::from_secrets(&[3; 32], [3; 32]);
    let mut c = proxied(&server, "203.0.113.1", &keys).await;
    assert_eq!(
        host(&mut c, genesis(&keys, r(3))).await,
        Body::Nack(ErrorBody {
            code: 17,
            diagnostic: Some(refusal::HOSTS_PER_IP.into()),
            details: None,
        })
    );
    // Another client address may host.
    let mut c = proxied(&server, "203.0.113.2", &keys).await;
    assert!(matches!(
        host(&mut c, genesis(&keys, r(3))).await,
        Body::ResourceHosted { .. }
    ));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A ready session as `keys`, through a trusted proxy reporting `client`.
async fn proxied(server: &Running, client: &str, keys: &PrincipalKeys) -> Client {
    let mut c = Client::try_connect(server.addr, &[("x-forwarded-for", client)])
        .await
        .unwrap();
    c.handshake(keys).await;
    c
}

struct FakeDisk(std::sync::atomic::AtomicU64);

impl lfcp_server::limits::DiskSpace for FakeDisk {
    fn available(&self, _: &std::path::Path) -> std::io::Result<u64> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn low_disk_space_refuses_hosting_and_writes_but_not_reads() {
    use std::sync::atomic::Ordering;
    let v = Vectors::load();
    let disk = std::sync::Arc::new(FakeDisk((3u64 << 30).into()));
    let dir = state_dir("quota-disk");
    let server = start(
        &dir,
        Options {
            abuse: Some(AbuseLimits {
                min_free_bytes: 2 << 30,
                disk_check_interval_ms: 100,
                ..AbuseLimits::default()
            }),
            disk: Some(disk.clone()),
            ..Options::default()
        },
    )
    .await;
    let mut owner = client(&server, &v.principal("owner")).await;
    assert!(matches!(
        host(&mut owner, v.cose(CHAIN[0])).await,
        Body::ResourceHosted { .. }
    ));
    for i in 1..CHAIN.len() {
        server
            .store
            .commit_control_record(v.cose(CHAIN[i]), v.record_id(CHAIN[i - 1]))
            .await
            .unwrap();
    }
    disk.0.store((2 << 30) - 1, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let other = genesis(&v.principal("owner"), ResourceId::from_bytes([7; 32]));
    assert_eq!(
        host(&mut owner, other).await,
        quota_exceeded(refusal::DISK_LOW)
    );
    assert_eq!(put_d1(&server, &v).await, quota_exceeded(refusal::DISK_LOW));
    // Reads keep working.
    let mut bob = client(&server, &v.principal("bob")).await;
    bob.request(Body::ResourceOpen {
        resource_id: v.resource(),
        control_heads: vec![],
        have: vec![],
        grant_ids: None,
        flags: Some(0),
    })
    .await;
    assert!(matches!(bob.recv().await.body, Body::ResourceOpened { .. }));
    // Space again: writes resume after the next reading.
    disk.0.store(3 << 30, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(matches!(put_d1(&server, &v).await, Body::Ack(_)));

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_total_cap_applies_in_every_mode() {
    let v = Vectors::load();
    let d1 = v.cose("D1_bob_epoch0_seq1").len() as u64;
    let (server, dir) = chain_server(
        &v,
        "quota-total",
        AbuseLimits {
            max_total_bytes: Some(chain_bytes(&v) + d1 - 1),
            min_free_bytes: 0,
            ..AbuseLimits::default()
        },
    )
    .await;
    let admin = admin_token(&server, &PrincipalKeys::from_secrets(&[9; 32], [9; 32])).await;
    let (status, _) = http(
        server.addr,
        "PUT",
        "/admin/hosting",
        Some(&admin),
        Some(json!({ "mode": "open" })),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        put_d1(&server, &v).await,
        quota_exceeded(refusal::SERVER_FULL)
    );
    let mut owner = client(&server, &v.principal("owner")).await;
    let other = genesis(&v.principal("owner"), ResourceId::from_bytes([7; 32]));
    assert_eq!(
        host(&mut owner, other).await,
        quota_exceeded(refusal::SERVER_FULL)
    );

    server.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
