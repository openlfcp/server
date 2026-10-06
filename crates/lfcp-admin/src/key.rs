//! The admin key file: the administrator's LFCP Principal secrets.
//!
//! ```json
//! {"format": "lfcp-admin-key-v1", "principal": "<id hex>",
//!  "ed25519_seed": "<32 bytes hex>", "x25519_private": "<32 bytes hex>"}
//! ```
//!
//! [`generate`] creates the file with mode 0600 and refuses to replace an
//! existing one. [`load`] refuses a file that its group or others may read
//! (Unix), and one whose secrets do not give its `principal`. Neither ever
//! prints a secret; the Principal ID is public.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use lfcp::base::{from_hex, to_hex, PrincipalId};
use lfcp::principal::PrincipalKeys;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::Error;

/// The `format` of a key file.
pub const FORMAT: &str = "lfcp-admin-key-v1";

/// The environment variable naming the key file when `--key` is absent.
pub const KEY_ENV: &str = "LFCP_ADMIN_KEY";

/// Create a new admin key at `path` (mode 0600, never overwritten) and
/// return its Principal ID.
pub fn generate(path: &Path) -> Result<PrincipalId, Error> {
    let mut secrets = Zeroizing::new([0u8; 64]);
    getrandom::fill(&mut secrets[..])
        .map_err(|e| Error::Io(format!("no operating-system randomness: {e}")))?;
    let seed: [u8; 32] = secrets[..32].try_into().expect("32 bytes");
    let x25519: [u8; 32] = secrets[32..].try_into().expect("32 bytes");
    let keys = PrincipalKeys::from_secrets(&seed, x25519);
    let id = *keys.descriptor().id();
    let text = Zeroizing::new(
        json!({
            "format": FORMAT,
            "principal": id.to_hex(),
            "ed25519_seed": to_hex(&secrets[..32]),
            "x25519_private": to_hex(&secrets[32..]),
        })
        .to_string()
            + "\n",
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| {
        Error::Io(match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                format!(
                    "{} already exists; refusing to replace a key",
                    path.display()
                )
            }
            _ => format!("cannot create {}: {e}", path.display()),
        })
    })?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| Error::Io(format!("cannot write {}: {e}", path.display())))?;
    Ok(id)
}

/// Load the admin key at `path`.
pub fn load(path: &Path) -> Result<PrincipalKeys, Error> {
    let shown = path.display();
    let metadata =
        std::fs::metadata(path).map_err(|e| Error::Io(format!("cannot read {shown}: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::Io(format!(
                "{shown} is readable by others (mode {mode:o}); run chmod 600 {shown}"
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("cannot read {shown}: {e}")))?,
    );
    let bad = || Error::Io(format!("{shown} is not an {FORMAT} key file"));
    let value: Value = serde_json::from_str(&text).map_err(|_| bad())?;
    if value["format"] != FORMAT {
        return Err(bad());
    }
    let secret = |field: &str| -> Result<Zeroizing<[u8; 32]>, Error> {
        let bytes = Zeroizing::new(
            value[field]
                .as_str()
                .and_then(|h| from_hex(h).ok())
                .ok_or_else(bad)?,
        );
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| bad())?;
        Ok(Zeroizing::new(array))
    };
    let seed = secret("ed25519_seed")?;
    let x25519 = secret("x25519_private")?;
    let keys = PrincipalKeys::from_secrets(&seed, *x25519);
    if value["principal"].as_str() != Some(keys.descriptor().id().to_hex().as_str()) {
        return Err(Error::Io(format!(
            "{shown}: its secrets do not give its principal; the file is damaged"
        )));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lfcp-admin-key-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_new_key_loads_and_is_never_replaced() {
        let dir = dir("new");
        let path = dir.join("admin.key");
        let id = generate(&path).unwrap();
        assert_eq!(load(&path).unwrap().descriptor().id(), &id);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(generate(&path), Err(Error::Io(e)) if e.contains("already exists")));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Two keys differ.
        assert_ne!(generate(&dir.join("other.key")).unwrap(), id);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damaged_or_exposed_keys_are_refused() {
        let dir = dir("bad");
        let path = dir.join("admin.key");
        generate(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let Err(Error::Io(e)) = load(&path) else {
                panic!("a readable key")
            };
            assert!(e.contains("chmod 600"), "{e}");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut value: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["principal"] = json!("00".repeat(32));
        std::fs::write(&path, value.to_string()).unwrap();
        assert!(matches!(load(&path), Err(Error::Io(e)) if e.contains("damaged")));
        std::fs::write(&path, "{}").unwrap();
        assert!(matches!(load(&path), Err(Error::Io(e)) if e.contains("not an")));
        assert!(load(&dir.join("missing.key")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
