#![doc = "Secure private-file credential storage for Unix hosts."]
#![cfg(unix)]

use std::{
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};

use bondry_secrets::{
    CredentialId, CredentialProtection, CredentialStore, CredentialStoreAccess,
    CredentialStoreCapabilities, CredentialStoreError, CredentialValue, MAX_CREDENTIAL_BYTES,
};
use nix::{
    errno::Errno,
    fcntl::{OFlag, open, openat, renameat},
    sys::stat::{FileStat, Mode, SFlag, fchmod, fstat},
    unistd::{UnlinkatFlags, fsync, geteuid, unlinkat},
};
use zeroize::Zeroizing;

const DIRECTORY_MODE: nix::libc::mode_t = 0o700;
const CREDENTIAL_MODE: nix::libc::mode_t = 0o600;
const TEMPORARY_NAME_ATTEMPTS: usize = 16;

/// A read-write credential store rooted in one private directory.
pub struct UnixFileCredentialStore {
    directory: OwnedFd,
    owner_user_id: u32,
}

impl UnixFileCredentialStore {
    /// Opens an existing absolute directory owned by the effective user.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CredentialStoreError> {
        let owner_user_id = geteuid().as_raw();
        let directory = open_absolute_directory(path.as_ref())?;
        validate_directory(&directory, owner_user_id)?;
        Ok(Self {
            directory,
            owner_user_id,
        })
    }

    fn validate_directory(&self) -> Result<(), CredentialStoreError> {
        validate_directory(&self.directory, self.owner_user_id)
    }

    fn open_credential(&self, id: &CredentialId) -> Result<Option<OwnedFd>, CredentialStoreError> {
        self.validate_directory()?;
        match openat(
            &self.directory,
            id.as_str(),
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                validate_credential(&descriptor, self.owner_user_id)?;
                Ok(Some(descriptor))
            }
            Err(Errno::ENOENT) => Ok(None),
            Err(error) => Err(map_open_error(error)),
        }
    }

    fn create_temporary(&self) -> Result<(String, OwnedFd), CredentialStoreError> {
        for _ in 0..TEMPORARY_NAME_ATTEMPTS {
            let name = temporary_name()?;
            match openat(
                &self.directory,
                name.as_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_CLOEXEC
                    | OFlag::O_NOFOLLOW,
                Mode::from_bits_truncate(CREDENTIAL_MODE),
            ) {
                Ok(descriptor) => {
                    if let Err(error) =
                        fchmod(&descriptor, Mode::from_bits_truncate(CREDENTIAL_MODE))
                    {
                        let _ =
                            unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir);
                        return Err(map_operation_error(error));
                    }
                    if let Err(error) =
                        validate_credential_metadata(&descriptor, self.owner_user_id)
                    {
                        let _ =
                            unlinkat(&self.directory, name.as_str(), UnlinkatFlags::NoRemoveDir);
                        return Err(error);
                    }
                    return Ok((name, descriptor));
                }
                Err(Errno::EEXIST) => {}
                Err(error) => return Err(map_open_error(error)),
            }
        }
        Err(CredentialStoreError::Unavailable)
    }
}

impl CredentialStore for UnixFileCredentialStore {
    fn capabilities(&self) -> CredentialStoreCapabilities {
        CredentialStoreCapabilities {
            protection: CredentialProtection::AccessControlled,
            access: CredentialStoreAccess::ReadWrite,
            supports_unattended_access: true,
        }
    }

    fn load(&self, id: &CredentialId) -> Result<Option<CredentialValue>, CredentialStoreError> {
        let Some(descriptor) = self.open_credential(id)? else {
            return Ok(None);
        };
        let expected_size = validated_credential_size(&descriptor, self.owner_user_id)?;
        let mut file = File::from(descriptor).take((MAX_CREDENTIAL_BYTES + 1) as u64);
        let mut bytes = Zeroizing::new(Vec::with_capacity(expected_size));
        file.read_to_end(&mut bytes)
            .map_err(|error| map_io_error(&error))?;
        if bytes.len() != expected_size {
            return Err(CredentialStoreError::InvalidMaterial);
        }
        CredentialValue::new(std::mem::take(&mut *bytes))
            .map(Some)
            .map_err(|_| CredentialStoreError::InvalidMaterial)
    }

    fn store(
        &self,
        id: &CredentialId,
        value: &CredentialValue,
    ) -> Result<(), CredentialStoreError> {
        let _ = self.open_credential(id)?;
        let (temporary_name, descriptor) = self.create_temporary()?;
        let mut cleanup = TemporaryCredential::new(&self.directory, temporary_name.as_str());
        let mut file = File::from(descriptor);
        file.write_all(value.expose())
            .map_err(|error| map_io_error(&error))?;
        file.sync_all().map_err(|error| map_io_error(&error))?;
        renameat(
            &self.directory,
            temporary_name.as_str(),
            &self.directory,
            id.as_str(),
        )
        .map_err(map_operation_error)?;
        cleanup.disarm();
        fsync(&self.directory).map_err(map_operation_error)
    }

    fn delete(&self, id: &CredentialId) -> Result<bool, CredentialStoreError> {
        if self.open_credential(id)?.is_none() {
            return Ok(false);
        }
        unlinkat(&self.directory, id.as_str(), UnlinkatFlags::NoRemoveDir)
            .map_err(map_operation_error)?;
        fsync(&self.directory).map_err(map_operation_error)?;
        Ok(true)
    }
}

struct TemporaryCredential<'a> {
    directory: &'a OwnedFd,
    name: &'a str,
    armed: bool,
}

impl<'a> TemporaryCredential<'a> {
    fn new(directory: &'a OwnedFd, name: &'a str) -> Self {
        Self {
            directory,
            name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryCredential<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(self.directory, self.name, UnlinkatFlags::NoRemoveDir);
        }
    }
}

#[cfg(target_os = "linux")]
fn open_absolute_directory(path: &Path) -> Result<OwnedFd, CredentialStoreError> {
    if !path.is_absolute() {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let mut directory = open(Path::new("/"), flags, Mode::empty()).map_err(map_open_error)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(&directory, Path::new(name), flags, Mode::empty())
                    .map_err(map_open_error)?;
            }
            _ => return Err(CredentialStoreError::UnsafeStorage),
        }
    }
    Ok(directory)
}

#[cfg(not(target_os = "linux"))]
fn open_absolute_directory(path: &Path) -> Result<OwnedFd, CredentialStoreError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(map_open_error)
}

fn validate_directory(
    descriptor: &OwnedFd,
    owner_user_id: u32,
) -> Result<(), CredentialStoreError> {
    let status = fstat(descriptor).map_err(map_operation_error)?;
    if !SFlag::from_bits_truncate(status.st_mode).contains(SFlag::S_IFDIR)
        || status.st_uid != owner_user_id
        || status.st_mode & 0o777 != DIRECTORY_MODE
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    Ok(())
}

fn validate_credential(
    descriptor: &OwnedFd,
    owner_user_id: u32,
) -> Result<(), CredentialStoreError> {
    validated_credential_size(descriptor, owner_user_id).map(drop)
}

fn validated_credential_size(
    descriptor: &OwnedFd,
    owner_user_id: u32,
) -> Result<usize, CredentialStoreError> {
    let status = validate_credential_metadata(descriptor, owner_user_id)?;
    if status.st_size <= 0 || status.st_size > MAX_CREDENTIAL_BYTES as i64 {
        return Err(CredentialStoreError::InvalidMaterial);
    }
    usize::try_from(status.st_size).map_err(|_| CredentialStoreError::InvalidMaterial)
}

fn validate_credential_metadata(
    descriptor: &OwnedFd,
    owner_user_id: u32,
) -> Result<FileStat, CredentialStoreError> {
    let status = fstat(descriptor).map_err(map_operation_error)?;
    if !SFlag::from_bits_truncate(status.st_mode).contains(SFlag::S_IFREG)
        || status.st_uid != owner_user_id
        || status.st_nlink != 1
        || status.st_mode & 0o777 != CREDENTIAL_MODE
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    Ok(status)
}

fn temporary_name() -> Result<String, CredentialStoreError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| CredentialStoreError::Unavailable)?;
    let mut name = String::with_capacity(20 + random.len() * 2);
    name.push_str(".bondry-credential-");
    for byte in random {
        use std::fmt::Write as _;
        write!(name, "{byte:02x}").map_err(|_| CredentialStoreError::Unavailable)?;
    }
    Ok(name)
}

fn map_open_error(error: Errno) -> CredentialStoreError {
    match error {
        Errno::EACCES | Errno::EPERM => CredentialStoreError::AccessDenied,
        Errno::ELOOP | Errno::ENOTDIR | Errno::EISDIR => CredentialStoreError::UnsafeStorage,
        _ => CredentialStoreError::Unavailable,
    }
}

fn map_operation_error(error: Errno) -> CredentialStoreError {
    match error {
        Errno::EACCES | Errno::EPERM => CredentialStoreError::AccessDenied,
        _ => CredentialStoreError::Unavailable,
    }
}

fn map_io_error(error: &std::io::Error) -> CredentialStoreError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => CredentialStoreError::AccessDenied,
        _ => CredentialStoreError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    use bondry_secrets::{
        CredentialId, CredentialProtection, CredentialStore, CredentialStoreAccess,
        CredentialStoreError, CredentialValue, MAX_CREDENTIAL_BYTES,
    };
    use tempfile::TempDir;

    use super::UnixFileCredentialStore;

    #[test]
    fn stores_replaces_loads_and_deletes_credentials() -> Result<(), Box<dyn std::error::Error>> {
        let directory = private_directory()?;
        let store = UnixFileCredentialStore::open(directory.path())?;
        let id = CredentialId::new("database-key")?;

        assert!(store.load(&id)?.is_none());
        store.store(&id, &CredentialValue::new(b"first".to_vec())?)?;
        assert_eq!(exposed(store.load(&id)?), Some(b"first".to_vec()));
        store.store(&id, &CredentialValue::new(b"second".to_vec())?)?;
        assert_eq!(exposed(store.load(&id)?), Some(b"second".to_vec()));

        let metadata = fs::symlink_metadata(directory.path().join(id.as_str()))?;
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(fs::read_dir(directory.path())?.count(), 1);
        assert!(store.delete(&id)?);
        assert!(!store.delete(&id)?);
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn reports_access_control_capabilities() -> Result<(), Box<dyn std::error::Error>> {
        let directory = private_directory()?;
        let capabilities = UnixFileCredentialStore::open(directory.path())?.capabilities();
        assert_eq!(
            capabilities.protection,
            CredentialProtection::AccessControlled
        );
        assert_eq!(capabilities.access, CredentialStoreAccess::ReadWrite);
        assert!(capabilities.supports_unattended_access);
        Ok(())
    }

    #[test]
    fn rejects_relative_symlinked_and_permissive_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            UnixFileCredentialStore::open("relative"),
            Err(CredentialStoreError::UnsafeStorage)
        ));

        let parent = private_directory()?;
        let target = parent.path().join("target");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        let link = parent.path().join("link");
        symlink(&target, &link)?;
        assert!(matches!(
            UnixFileCredentialStore::open(&link),
            Err(CredentialStoreError::UnsafeStorage)
        ));

        fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;
        assert!(matches!(
            UnixFileCredentialStore::open(&target),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        Ok(())
    }

    #[test]
    fn rejects_symlinked_hardlinked_and_permissive_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = private_directory()?;
        let store = UnixFileCredentialStore::open(directory.path())?;
        let id = CredentialId::new("tls-identity")?;
        let path = directory.path().join(id.as_str());
        let outside = directory.path().join("outside");
        fs::write(&outside, b"outside")?;
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;

        symlink(&outside, &path)?;
        assert!(matches!(
            store.load(&id),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        assert!(matches!(
            store.store(&id, &CredentialValue::new(b"replacement".to_vec())?),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        assert_eq!(fs::read(&outside)?, b"outside");
        fs::remove_file(&path)?;

        fs::hard_link(&outside, &path)?;
        assert!(matches!(
            store.load(&id),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        fs::remove_file(&path)?;

        fs::write(&path, b"credential")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            store.load(&id),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_and_oversized_persisted_material() -> Result<(), Box<dyn std::error::Error>> {
        let directory = private_directory()?;
        let store = UnixFileCredentialStore::open(directory.path())?;
        let id = CredentialId::new("client-token")?;
        let path = directory.path().join(id.as_str());

        fs::write(&path, [])?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(matches!(
            store.load(&id),
            Err(CredentialStoreError::InvalidMaterial)
        ));

        fs::write(&path, vec![0; MAX_CREDENTIAL_BYTES + 1])?;
        assert!(matches!(
            store.load(&id),
            Err(CredentialStoreError::InvalidMaterial)
        ));
        Ok(())
    }

    #[test]
    fn revalidates_directory_permissions_before_each_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = private_directory()?;
        let store = UnixFileCredentialStore::open(directory.path())?;
        let id = CredentialId::new("database-key")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;

        assert!(matches!(
            store.store(&id, &CredentialValue::new(b"secret".to_vec())?),
            Err(CredentialStoreError::UnsafeStorage)
        ));
        Ok(())
    }

    fn private_directory() -> Result<TempDir, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn exposed(value: Option<CredentialValue>) -> Option<Vec<u8>> {
        value.map(|value| value.expose().to_vec())
    }
}
