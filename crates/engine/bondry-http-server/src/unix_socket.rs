use std::{
    io,
    os::unix::{
        ffi::OsStrExt as _,
        fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};

/// Conservative pathname capacity supported by macOS and Linux Unix sockets.
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const SOCKET_MODE: u32 = 0o600;
const LIVE_PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Filesystem and peer policy for one Unix-domain listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixSocketConfiguration {
    path: PathBuf,
    owner_user_id: u32,
    peer_user_id: u32,
}

impl UnixSocketConfiguration {
    /// Creates an explicit socket path, owner, and accepted peer policy.
    pub fn new(
        path: impl Into<PathBuf>,
        owner_user_id: u32,
        peer_user_id: u32,
    ) -> Result<Self, UnixSocketConfigurationError> {
        let path = path.into();
        validate_path(&path)?;
        Ok(Self {
            path,
            owner_user_id,
            peer_user_id,
        })
    }

    /// Returns the configured socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the required owner user ID.
    #[must_use]
    pub const fn owner_user_id(&self) -> u32 {
        self.owner_user_id
    }

    /// Returns the only accepted peer user ID.
    #[must_use]
    pub const fn peer_user_id(&self) -> u32 {
        self.peer_user_id
    }
}

/// An invalid Unix-domain listener configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UnixSocketConfigurationError {
    /// The path must be absolute and contain a file name.
    #[error("Unix socket path must be absolute and contain a file name")]
    InvalidPath,
    /// The encoded path does not fit the supported Unix socket address.
    #[error("Unix socket path exceeds the supported byte length")]
    PathTooLong,
}

pub(crate) struct BoundUnixListener {
    listener: UnixListener,
    owner: SocketPathOwner,
    peer_user_id: u32,
}

impl BoundUnixListener {
    pub(crate) async fn bind(configuration: &UnixSocketConfiguration) -> io::Result<Self> {
        validate_parent(configuration)?;
        recover_stale_socket(configuration).await?;
        let listener = UnixListener::bind(&configuration.path)?;
        let owner = secure_bound_socket(configuration)?;
        Ok(Self {
            listener,
            owner,
            peer_user_id: configuration.peer_user_id,
        })
    }

    pub(crate) async fn accept(&self) -> io::Result<Option<UnixStream>> {
        let (stream, _) = self.listener.accept().await?;
        let peer_user_id = peer_user_id(&stream)?;
        Ok((peer_user_id == self.peer_user_id).then_some(stream))
    }

    pub(crate) fn cleanup(&mut self) -> io::Result<()> {
        self.owner.remove()
    }
}

fn validate_path(path: &Path) -> Result<(), UnixSocketConfigurationError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute() || path.file_name().is_none() || bytes.is_empty() || bytes.contains(&0) {
        return Err(UnixSocketConfigurationError::InvalidPath);
    }
    if bytes.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(UnixSocketConfigurationError::PathTooLong);
    }
    Ok(())
}

fn validate_parent(configuration: &UnixSocketConfiguration) -> io::Result<()> {
    let parent = configuration
        .path
        .parent()
        .ok_or_else(|| invalid_data("Unix socket path has no parent"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != configuration.owner_user_id
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix socket parent directory is not private to the configured owner",
        ));
    }
    let effective_user_id = nix::unistd::geteuid().as_raw();
    if effective_user_id != configuration.owner_user_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix socket owner does not match the effective user",
        ));
    }
    Ok(())
}

async fn recover_stale_socket(configuration: &UnixSocketConfiguration) -> io::Result<()> {
    let Some(identity) = socket_identity(&configuration.path)? else {
        return Ok(());
    };
    if identity.owner_user_id != configuration.owner_user_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing Unix socket has a different owner",
        ));
    }
    if identity.mode != SOCKET_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing Unix socket mode is not private",
        ));
    }
    match tokio::time::timeout(LIVE_PROBE_TIMEOUT, UnixStream::connect(&configuration.path)).await {
        Ok(Ok(_)) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "Unix socket already accepts connections",
        )),
        Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => remove_owned_path(
            &configuration.path,
            Some(identity),
            configuration.owner_user_id,
        ),
        Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Unix socket liveness probe timed out",
        )),
    }
}

fn secure_bound_socket(configuration: &UnixSocketConfiguration) -> io::Result<SocketPathOwner> {
    let initial = socket_identity(&configuration.path)?
        .ok_or_else(|| invalid_data("bound Unix socket path disappeared"))?;
    if initial.owner_user_id != configuration.owner_user_id {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bound Unix socket ownership is invalid",
        ));
    }
    let mut owner = SocketPathOwner {
        path: configuration.path.clone(),
        identity: Some(initial),
        owner_user_id: configuration.owner_user_id,
    };
    std::fs::set_permissions(
        &configuration.path,
        std::fs::Permissions::from_mode(SOCKET_MODE),
    )?;
    let secured = socket_identity(&configuration.path)?
        .ok_or_else(|| invalid_data("bound Unix socket path disappeared"))?;
    if !initial.same_object(secured) || secured.mode != SOCKET_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bound Unix socket identity or mode changed",
        ));
    }
    owner.identity = Some(secured);
    Ok(owner)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    owner_user_id: u32,
    mode: u32,
}

impl SocketIdentity {
    const fn same_object(self, other: Self) -> bool {
        self.device == other.device
            && self.inode == other.inode
            && self.owner_user_id == other.owner_user_id
    }
}

fn socket_identity(path: &Path) -> io::Result<Option<SocketIdentity>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(invalid_data("Unix socket path is not a socket"));
    }
    Ok(Some(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_user_id: metadata.uid(),
        mode: metadata.mode() & 0o7777,
    }))
}

fn remove_owned_path(
    path: &Path,
    expected: Option<SocketIdentity>,
    owner_user_id: u32,
) -> io::Result<()> {
    let Some(current) = socket_identity(path)? else {
        return Ok(());
    };
    if current.owner_user_id != owner_user_id
        || expected.is_some_and(|value| !value.same_object(current))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unix socket path ownership changed",
        ));
    }
    std::fs::remove_file(path)
}

struct SocketPathOwner {
    path: PathBuf,
    identity: Option<SocketIdentity>,
    owner_user_id: u32,
}

impl SocketPathOwner {
    fn remove(&mut self) -> io::Result<()> {
        let Some(identity) = self.identity.take() else {
            return Ok(());
        };
        remove_owned_path(&self.path, Some(identity), self.owner_user_id)
    }
}

impl Drop for SocketPathOwner {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_user_id(stream: &UnixStream) -> io::Result<u32> {
    nix::unistd::getpeereid(stream)
        .map(|(user, _)| user.as_raw())
        .map_err(io::Error::other)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_user_id(stream: &UnixStream) -> io::Result<u32> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(io::Error::other)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn peer_user_id(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix peer credentials are unavailable",
    ))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use tempfile::tempdir;

    use super::{
        MAX_UNIX_SOCKET_PATH_BYTES, UnixSocketConfiguration, UnixSocketConfigurationError,
    };

    #[test]
    fn validates_absolute_bounded_paths() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("server.sock");

        let configuration = UnixSocketConfiguration::new(&path, 501, 502)?;

        assert_eq!(configuration.path(), path);
        assert_eq!(configuration.owner_user_id(), 501);
        assert_eq!(configuration.peer_user_id(), 502);
        assert_eq!(MAX_UNIX_SOCKET_PATH_BYTES, 103);
        assert_eq!(
            UnixSocketConfiguration::new("relative.sock", 501, 501),
            Err(UnixSocketConfigurationError::InvalidPath)
        );
        Ok(())
    }

    #[test]
    fn rejects_paths_beyond_the_portable_capacity() {
        let path = format!("/{}", "s".repeat(MAX_UNIX_SOCKET_PATH_BYTES));

        assert_eq!(
            UnixSocketConfiguration::new(path, 501, 501),
            Err(UnixSocketConfigurationError::PathTooLong)
        );
    }

    #[test]
    fn parent_policy_rejects_group_access() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750))?;
        let user_id = nix::unistd::geteuid().as_raw();
        let configuration =
            UnixSocketConfiguration::new(directory.path().join("server.sock"), user_id, user_id)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let error = runtime
            .block_on(super::BoundUnixListener::bind(&configuration))
            .err()
            .ok_or("permissive parent was accepted")?;

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        Ok(())
    }
}
