//! `lfcp-admin` against a real server (POST-014): the server runs in this
//! process on a loopback port, the CLI is the built binary. A fresh server
//! is paired; the hosting policy and a quota override are set and read
//! back; a wrong key, a replayed proof and an https URL are refused; no
//! secret reaches the output.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use lfcp_admin::client::{proof_body, Admin};
use lfcp_admin::http::{request, Url};
use lfcp_server::admin::PURPOSE_SESSION;
use lfcp_server::config::Config;
use lfcp_server::identity::FileIdentity;
use lfcp_server::server::Server;
use lfcp_server::session::Lfcp;
use lfcp_server::store::Store;
use serde_json::{json, Value};

struct Running {
    url: String,
    code: String,
    dir: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = (&mut self.task).await;
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

/// A fresh, unpaired server on a loopback port.
async fn start(name: &str) -> Running {
    let dir = std::env::temp_dir().join(format!("lfcp-admin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state");
    let config = Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        state_dir: state.clone(),
        ..Config::default()
    };
    let identity = Arc::new(FileIdentity::load_or_create(&state).unwrap());
    let store = Arc::new(Store::open(&state).unwrap());
    let server = Server::bind(config.clone(), identity, store.clone())
        .await
        .unwrap();
    let addr: SocketAddr = server.local_addr().unwrap();
    let (admin, code) = lfcp_server::admin::Admin::open(
        store.clone(),
        server.server_id(),
        &config,
        Arc::new(lfcp_server::rng::OsRandom),
        lfcp_server::admin::SETUP_TTL,
    )
    .await
    .unwrap();
    let sessions = Lfcp::new(store, &config).with_hosting(admin.hosting());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(server.with_admin(admin).run(sessions, async {
        let _ = stopped.await;
    }));
    Running {
        url: format!("http://{addr}"),
        code: code
            .expect("a fresh server has a setup code")
            .expose()
            .to_owned(),
        dir,
        stop: Some(stop),
        task,
    }
}

/// Run the CLI with `args` (and `stdin`), off the runtime's threads.
async fn cli(args: &[&str], stdin: Option<&str>) -> Output {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let stdin = stdin.map(str::to_owned);
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_lfcp-admin"))
            .args(&args)
            .env_remove("LFCP_ADMIN_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let mut input = child.stdin.take().unwrap();
            if let Some(text) = stdin {
                input.write_all(text.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8(output.stdout.clone()).unwrap(),
        String::from_utf8(output.stderr.clone()).unwrap(),
    )
}

/// Run the CLI as the administrator with `key`; its JSON output.
async fn json(server: &Running, key: &Path, args: &[&str]) -> Value {
    let mut all = vec!["--url", &server.url, "--key", key.to_str().unwrap()];
    all.extend_from_slice(args);
    let output = cli(&all, None).await;
    let (out, err) = text(&output);
    assert!(output.status.success(), "{args:?}: {err}");
    serde_json::from_str(&out).unwrap_or_else(|_| panic!("{args:?}: not JSON: {out}"))
}

fn secrets_of(key: &Path) -> Vec<String> {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(key).unwrap()).unwrap();
    ["ed25519_seed", "x25519_private"]
        .iter()
        .map(|f| value[f].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_server_is_paired_and_administered() {
    let server = start("flow").await;
    let key = server.dir.join("admin.key");
    let k = key.to_str().unwrap();

    // keygen: prints the Principal, never the secrets; never replaces.
    let output = cli(&["--key", k, "keygen"], None).await;
    let (out, _) = text(&output);
    assert!(output.status.success());
    let principal = out
        .lines()
        .find_map(|l| l.strip_prefix("principal: "))
        .unwrap()
        .to_owned();
    for secret in secrets_of(&key) {
        assert!(!out.contains(&secret));
    }
    let again = cli(&["--key", k, "keygen"], None).await;
    assert_eq!(again.status.code(), Some(1));
    assert!(text(&again).1.contains("already exists"));

    // pair, with the code on stdin: it appears in no output.
    let output = cli(
        &[
            "--url",
            &server.url,
            "--key",
            k,
            "pair",
            "--setup-code",
            "-",
        ],
        Some(&format!("{}\n", server.code)),
    )
    .await;
    let (out, err) = text(&output);
    assert!(output.status.success(), "{err}");
    assert_eq!(
        out.trim(),
        format!("paired: {principal} is the server's administrator")
    );
    assert!(!out.contains(&server.code) && !err.contains(&server.code));
    // The code is spent.
    let output = cli(
        &[
            "--url",
            &server.url,
            "--key",
            k,
            "pair",
            "--setup-code",
            &server.code,
        ],
        None,
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).1.contains("HTTP 410"), "{}", text(&output).1);

    let status = json(&server, &key, &["status"]).await;
    assert_eq!(status["admins"], json!([principal]));

    // The hosting policy: quota by default, set and read back.
    assert_eq!(
        json(&server, &key, &["hosting", "get"]).await,
        json!({ "mode": "quota" })
    );
    json(&server, &key, &["hosting", "set", "open"]).await;
    assert_eq!(
        json(&server, &key, &["hosting", "get"]).await,
        json!({ "mode": "open" })
    );
    let other = "ab".repeat(32);
    let credentials = server.dir.join("credentials");
    std::fs::write(&credentials, "# deploy keys\n0102ff\n").unwrap();
    let set = json(
        &server,
        &key,
        &[
            "hosting",
            "set",
            "allow_list",
            "--principal",
            &other,
            "--credentials-file",
            credentials.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(set["credentials"], json!(1));
    let got = json(&server, &key, &["hosting", "get"]).await;
    assert_eq!(got["mode"], json!("allow_list"));
    assert_eq!(got["principals"], json!([other]));
    json(&server, &key, &["hosting", "set", "quota"]).await;

    // A quota override: set, read back, list, clear.
    let set = json(
        &server,
        &key,
        &[
            "quota",
            "set",
            &other,
            "--resources",
            "0",
            "--bytes",
            "1000",
        ],
    )
    .await;
    assert_eq!(
        set["override"],
        json!({ "resources": 0, "bytes": 1000, "resource_bytes": null })
    );
    let got = json(&server, &key, &["quota", "get", &other]).await;
    assert_eq!(got["quota"]["resources"], json!(0));
    assert_eq!(got["usage"], json!({ "resources": 0, "bytes": 0 }));
    let list = json(&server, &key, &["quota", "list"]).await;
    assert_eq!(list["overrides"][0]["principal"], json!(other));
    let cleared = json(&server, &key, &["quota", "clear", &other]).await;
    assert_eq!(cleared["override"], json!(null));
    assert_eq!(
        json(&server, &key, &["quota", "list"]).await["overrides"],
        json!([])
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_key_and_a_replayed_proof_are_refused() {
    let server = start("refusals").await;
    let admin_key = server.dir.join("admin.key");
    let stranger_key = server.dir.join("stranger.key");
    lfcp_admin::key::generate(&admin_key).unwrap();
    lfcp_admin::key::generate(&stranger_key).unwrap();
    let url = Url::parse(&server.url).unwrap();
    let admin = Admin::new(url.clone(), lfcp_admin::key::load(&admin_key).unwrap());
    admin.pair(&server.code).unwrap();

    // Another key is no administrator.
    let output = cli(
        &[
            "--url",
            &server.url,
            "--key",
            stranger_key.to_str().unwrap(),
            "status",
        ],
        None,
    )
    .await;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        text(&output).1.trim(),
        "lfcp-admin: the server refused: not a server administrator (HTTP 403)"
    );

    // The administrator's own session proof works once.
    let keys = lfcp_admin::key::load(&admin_key).unwrap();
    let (server_id, challenge) = admin.challenge().unwrap();
    let body = proof_body(&keys, PURPOSE_SESSION, &server_id, &challenge);
    let first = request(&url, "POST", "/admin/session", None, Some(&body)).unwrap();
    assert_eq!(first.status, 200);
    let replay = request(&url, "POST", "/admin/session", None, Some(&body)).unwrap();
    assert_eq!(replay.status, 401);
    assert_eq!(replay.body["error"], json!("proof refused"));

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_errors_are_explained() {
    let dir = std::env::temp_dir().join(format!("lfcp-admin-usage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("admin.key");
    lfcp_admin::key::generate(&key).unwrap();
    let k = key.to_str().unwrap();
    for (args, message) in [
        (vec!["status"], "no admin key"),
        (
            vec!["--url", "https://sync.example.org", "--key", k, "status"],
            "https is not supported",
        ),
        (vec!["--key", k, "launch"], "unknown command"),
        (
            vec!["--key", k, "quota", "get", "xyz"],
            "not a 64-hex Principal ID",
        ),
        (
            vec!["--key", k, "quota", "set", &"ab".repeat(32)],
            "quota set needs",
        ),
        (vec!["--key", k, "pair"], "pair needs --setup-code"),
    ] {
        let output = cli(&args, None).await;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            text(&output).1.contains(message),
            "{args:?}: {}",
            text(&output).1
        );
    }
    // Nothing listens: a readable network error, exit 1.
    let output = cli(&["--url", "http://127.0.0.1:9", "--key", k, "status"], None).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output).1.contains("is the SSH tunnel up?"));
    std::fs::remove_dir_all(&dir).unwrap();
}
