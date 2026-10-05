//! The server links the LFCP protocol core only: never Automerge or the
//! Shared Objects profile (AGENT-OPERATING-GUIDE §6.4), and nothing of the
//! editor world.

use std::process::Command;

fn cargo_tree(args: &[&str]) -> String {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--manifest-path", manifest, "-e", "normal"])
        .args(args)
        .output()
        .expect("cargo tree");
    assert!(
        out.status.success(),
        "cargo tree: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn no_automerge_or_shared_objects_feature() {
    let tree = cargo_tree(&["--prefix", "none"]);
    for forbidden in ["automerge", "hexane", "obsidian", "codemirror"] {
        assert!(
            !tree.lines().any(|l| l.starts_with(forbidden)),
            "{forbidden} is in the server's dependency tree"
        );
    }
    let features = cargo_tree(&["-e", "features", "-i", "lfcp"]);
    assert!(
        !features.contains("shared-objects"),
        "lfcp is built with shared-objects:\n{features}"
    );

    let mut crates: Vec<&str> = tree
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.trim_end_matches(" (*)"))
        .collect();
    crates.sort_unstable();
    crates.dedup();
    eprintln!("normal dependency tree: {} unique crates", crates.len());
}
