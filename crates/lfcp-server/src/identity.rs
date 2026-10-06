//! The server's stable 32-byte ID (WIRE-01 §35 CHALLENGE field 3, §37
//! READY field 1).
//!
//! The ID is opaque: WIRE-01 has the server sign nothing, so there is no
//! server key. It is random, created once, and the same for every
//! connection and every process start. It is never derived from the host
//! name or an address, and never silently regenerated: a missing file is
//! created, but a file that exists and cannot be read is an error.
//!
//! [`FileIdentity`] keeps it in `<state_dir>/server-id` as 64 lowercase hex
//! characters and a newline, created with create-new, mode 0600 and fsync.
//! Later the store (LFCP-045) may hold it behind the same
//! [`ServerIdentity`] trait.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use crate::rng;

/// The name of the identity file in the state directory.
pub const SERVER_ID_FILE: &str = "server-id";

/// A server ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerId([u8; 32]);

impl ServerId {
    /// The ID with these bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> ServerId {
        ServerId(bytes)
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 64 lowercase hex characters.
    pub fn to_hex(&self) -> String {
        lfcp::base::to_hex(&self.0)
    }
}

impl fmt::Debug for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerId({})", self.to_hex())
    }
}

/// Where a server gets its ID from.
pub trait ServerIdentity: Send + Sync {
    /// The ID: the same value on every call.
    fn server_id(&self) -> ServerId;
}

/// Why the identity could not be loaded or created.
#[derive(Debug)]
pub enum IdentityError {
    /// The state directory or the file could not be created or read.
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        error: std::io::Error,
    },
    /// The file exists but does not hold a server ID. It is not replaced.
    Corrupt {
        /// The file.
        path: PathBuf,
    },
    /// The operating system's random source failed.
    Random(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Io { path, error } => write!(f, "{}: {error}", path.display()),
            IdentityError::Corrupt { path } => write!(
                f,
                "{} does not hold a server ID (64 hex characters); refusing to replace it",
                path.display()
            ),
            IdentityError::Random(e) => write!(f, "no randomness for a server ID: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// A server ID kept in a file in the state directory.
#[derive(Clone, Debug)]
pub struct FileIdentity {
    id: ServerId,
    path: PathBuf,
}

impl FileIdentity {
    /// Load `<state_dir>/server-id`, or create it with a fresh random ID if
    /// it does not exist. The state directory is created if needed.
    pub fn load_or_create(state_dir: &Path) -> Result<FileIdentity, IdentityError> {
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |error| IdentityError::Io { path, error }
        };
        crate::private::create_dir(state_dir).map_err(io(state_dir))?;
        let path = state_dir.join(SERVER_ID_FILE);
        match create(&path) {
            Ok(id) => {
                // Make the new directory entry durable too (Unix only:
                // Windows cannot open a directory as a file).
                crate::private::sync_dir(state_dir).map_err(io(state_dir))?;
                Ok(FileIdentity { id, path })
            }
            Err(Created::Exists) => Ok(FileIdentity {
                id: read(&path)?,
                path,
            }),
            Err(Created::Failed(e)) => Err(e),
        }
    }

    /// The identity file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ServerIdentity for FileIdentity {
    fn server_id(&self) -> ServerId {
        self.id
    }
}

enum Created {
    Exists,
    Failed(IdentityError),
}

/// Create the file with a new ID, failing if it already exists.
fn create(path: &Path) -> Result<ServerId, Created> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(Created::Exists),
        Err(error) => {
            return Err(Created::Failed(IdentityError::Io {
                path: path.into(),
                error,
            }))
        }
    };
    let id = ServerId(rng::random_bytes().map_err(|e| Created::Failed(IdentityError::Random(e)))?);
    let fail = |error| {
        Created::Failed(IdentityError::Io {
            path: path.into(),
            error,
        })
    };
    file.write_all(format!("{}\n", id.to_hex()).as_bytes())
        .map_err(fail)?;
    file.sync_all().map_err(fail)?;
    Ok(id)
}

/// Read an existing identity file.
fn read(path: &Path) -> Result<ServerId, IdentityError> {
    let mut text = String::new();
    File::open(path)
        .and_then(|f| f.take(1024).read_to_string(&mut text))
        .map_err(|error| IdentityError::Io {
            path: path.into(),
            error,
        })?;
    let corrupt = || IdentityError::Corrupt { path: path.into() };
    let hex = text.strip_suffix('\n').unwrap_or(&text);
    let bytes = lfcp::base::from_hex(hex).map_err(|_| corrupt())?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| corrupt())?;
    Ok(ServerId(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh empty directory under the system temp directory.
    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lfcp-server-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn creates_once_then_loads_the_same_id() {
        let dir = temp_dir("identity-stable");
        let first = FileIdentity::load_or_create(&dir).unwrap();
        let second = FileIdentity::load_or_create(&dir).unwrap();
        assert_eq!(first.server_id(), second.server_id());
        assert_eq!(first.server_id(), first.server_id());
        assert_eq!(first.server_id().as_bytes().len(), 32);
        let text = std::fs::read_to_string(first.path()).unwrap();
        assert_eq!(text, format!("{}\n", first.server_id().to_hex()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(first.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every platform (the Windows CI job included): a state directory that
    /// does not exist yet, several levels deep, is created with the
    /// identity, and the identity loads again from it. On Windows this
    /// failed with "Access is denied" (os error 5) when the directory was
    /// opened as a file to sync it.
    #[test]
    fn creates_a_fresh_nested_state_directory_and_loads_it_again() {
        let root = temp_dir("identity-nested");
        let dir = root.join("a").join("b").join("state");
        let created = FileIdentity::load_or_create(&dir).unwrap();
        assert!(created.path().is_file());
        let loaded = FileIdentity::load_or_create(&dir).unwrap();
        assert_eq!(created.server_id(), loaded.server_id());
        crate::private::sync_dir(&dir).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn different_state_directories_get_different_ids() {
        let (a, b) = (temp_dir("identity-a"), temp_dir("identity-b"));
        let id_a = FileIdentity::load_or_create(&a).unwrap().server_id();
        let id_b = FileIdentity::load_or_create(&b).unwrap().server_id();
        assert_ne!(id_a, id_b);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn a_corrupt_file_is_an_error_and_is_kept() {
        let dir = temp_dir("identity-corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SERVER_ID_FILE);
        for bad in [
            "",
            "abc\n",
            &"0".repeat(62),
            &"g".repeat(64),
            &format!("{}\n\n", "0".repeat(64)),
        ] {
            std::fs::write(&path, bad).unwrap();
            let err = FileIdentity::load_or_create(&dir).unwrap_err();
            assert!(
                matches!(err, IdentityError::Corrupt { .. }),
                "{bad:?}: {err}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad, "not replaced");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn debug_shows_hex() {
        let id = ServerId::from_bytes([0xab; 32]);
        assert_eq!(format!("{id:?}"), format!("ServerId({})", "ab".repeat(32)));
    }
}
