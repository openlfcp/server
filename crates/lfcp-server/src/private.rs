//! Owner-only file system state (security review L5): the state directory
//! is created with mode 0700, and the database files are kept at 0600. On
//! other platforms these are plain creates.
//!
//! An existing state directory keeps its mode: an operator (or a container
//! volume) may have set it on purpose. The database files are tightened
//! at every open, since a server from before this rule left them at the
//! umask default.

use std::io;
use std::path::Path;

/// Create `dir` and any missing parents; the directories created here get
/// mode 0700.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Make the entries of `dir` durable, so that a file just created in it
/// survives a crash: an fsync of the directory on Unix. Windows has no
/// portable equivalent: a directory cannot be opened as a file (that is
/// `Access is denied`, os error 5, unless the handle is opened with
/// FILE_FLAG_BACKUP_SEMANTICS), and NTFS journals its metadata. There this
/// does nothing.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Create `path` empty with mode 0600 if it does not exist.
pub fn create_file(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other.map(drop),
    }
}

/// Set `path` to mode 0600 if it exists.
pub fn restrict(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            other => other?,
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
