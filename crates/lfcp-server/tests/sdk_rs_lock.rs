//! sdk-rs is consumed from the sibling checkout (`../sdk-rs`, a path
//! dependency). sdk-rs.lock records the commit the server is built and
//! tested against; this test fails when the checkout is at another commit
//! and warns when the lfcp crate has uncommitted changes.

use std::path::Path;
use std::process::Command;

#[test]
fn the_sibling_sdk_rs_checkout_is_at_the_locked_commit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("sdk-rs.lock")).expect("sdk-rs.lock"),
    )
    .expect("JSON");
    let locked = lock["commit"].as_str().expect("commit");
    assert_eq!(lock["repository"], "openlfcp/sdk-rs");
    assert!(
        locked.len() == 40 && locked.bytes().all(|b| b.is_ascii_hexdigit()),
        "full commit ID"
    );

    let sdk = root.join("../sdk-rs");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&sdk)
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?} in {}", sdk.display());
        String::from_utf8(out.stdout).unwrap()
    };
    let head = git(&["rev-parse", "HEAD"]);
    assert_eq!(
        head.trim(),
        locked,
        "../sdk-rs is at {} but sdk-rs.lock pins {locked}: update sdk-rs.lock deliberately, or check out the locked commit",
        head.trim()
    );
    let dirty = git(&[
        "status",
        "--porcelain",
        "--",
        "crates/lfcp",
        "Cargo.toml",
        "Cargo.lock",
    ]);
    if !dirty.trim().is_empty() {
        eprintln!("warning: ../sdk-rs has uncommitted changes in the lfcp crate:\n{dirty}");
    }
}
