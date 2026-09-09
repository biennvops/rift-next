use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rift_ipc::{LocalEndpointDescriptor, LocalTransport, RuntimeDescriptor};

use crate::DaemonError;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) const IDENTITY_FILE_NAME: &str = "identity.key";
pub(crate) const TRUST_FILE_NAME: &str = "trust.journal";
pub(crate) const LOCK_FILE_NAME: &str = "runtime.lock";
pub(crate) const DESCRIPTOR_FILE_NAME: &str = "runtime.json";
#[cfg(unix)]
pub(crate) const SOCKET_FILE_NAME: &str = "ipc.sock";

pub(crate) fn prepare_data_directory(path: &Path) -> Result<(), DaemonError> {
    fs::create_dir_all(path).map_err(|source| io_error("create data directory", source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect data directory", source))?;
    if !metadata.file_type().is_dir() {
        return Err(DaemonError::InvalidDataDirectory(
            "data directory path is not a directory",
        ));
    }
    apply_directory_permissions(path)?;
    verify_directory_permissions(path)?;
    Ok(())
}

pub(crate) struct RuntimeLock {
    file: File,
}

impl RuntimeLock {
    pub(crate) fn acquire(data_dir: &Path) -> Result<Self, DaemonError> {
        let path = data_dir.join(LOCK_FILE_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|source| io_error("open runtime lock", source))?;
        apply_file_permissions(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { file }),
            Err(fs::TryLockError::WouldBlock) => Err(DaemonError::AlreadyRunning),
            Err(fs::TryLockError::Error(source)) => Err(io_error("acquire runtime lock", source)),
        }
    }

    pub(crate) fn release(self) -> Result<(), DaemonError> {
        self.file
            .unlock()
            .map_err(|source| io_error("release runtime lock", source))
    }
}

pub(crate) struct RuntimeArtifacts {
    descriptor_path: PathBuf,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl RuntimeArtifacts {
    pub(crate) fn prepare(data_dir: &Path) -> Result<Self, DaemonError> {
        let descriptor_path = data_dir.join(DESCRIPTOR_FILE_NAME);
        remove_if_present(&descriptor_path, "remove stale runtime descriptor")?;
        #[cfg(unix)]
        {
            let socket_path = data_dir.join(SOCKET_FILE_NAME);
            remove_if_present(&socket_path, "remove stale IPC socket")?;
            Ok(Self {
                descriptor_path,
                socket_path,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { descriptor_path })
        }
    }

    pub(crate) fn descriptor_path(&self) -> &Path {
        &self.descriptor_path
    }

    #[cfg(unix)]
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn publish(&self, descriptor: &RuntimeDescriptor) -> Result<(), DaemonError> {
        let bytes = serde_json::to_vec_pretty(descriptor).map_err(DaemonError::DescriptorEncode)?;
        write_atomic_private(&self.descriptor_path, &bytes)
    }

    pub(crate) fn unpublish_descriptor(&self) -> Result<(), DaemonError> {
        remove_if_present(&self.descriptor_path, "remove runtime descriptor")
    }

    pub(crate) fn cleanup(&self) -> Result<(), DaemonError> {
        self.unpublish_descriptor()?;
        #[cfg(unix)]
        remove_if_present(&self.socket_path, "remove IPC socket")?;
        Ok(())
    }
}

impl Drop for RuntimeArtifacts {
    fn drop(&mut self) {
        drop(remove_if_present(
            &self.descriptor_path,
            "remove runtime descriptor",
        ));
        #[cfg(unix)]
        drop(remove_if_present(&self.socket_path, "remove IPC socket"));
    }
}

#[cfg(unix)]
pub(crate) type LocalStream = tokio::net::UnixStream;
#[cfg(windows)]
pub(crate) type LocalStream = tokio::net::windows::named_pipe::NamedPipeServer;

#[cfg(unix)]
pub(crate) struct LocalListener {
    listener: tokio::net::UnixListener,
}

#[cfg(unix)]
impl LocalListener {
    pub(crate) fn bind(
        artifacts: &RuntimeArtifacts,
        _runtime_id: &str,
    ) -> Result<(Self, LocalEndpointDescriptor), DaemonError> {
        use std::os::unix::ffi::OsStrExt;

        let path = artifacts.socket_path();
        let maximum = unix_socket_path_max();
        let actual = path.as_os_str().as_bytes().len();
        if actual > maximum {
            return Err(DaemonError::IpcAddressTooLong { actual, maximum });
        }
        let listener = tokio::net::UnixListener::bind(path)
            .map_err(|source| io_error("bind Unix IPC socket", source))?;
        apply_file_permissions(path)?;
        verify_file_permissions(path)?;
        let address = path
            .to_str()
            .ok_or(DaemonError::NonUtf8IpcAddress)?
            .to_owned();
        Ok((
            Self { listener },
            LocalEndpointDescriptor {
                transport: LocalTransport::Unix,
                address,
            },
        ))
    }

    pub(crate) async fn accept(&mut self) -> io::Result<LocalStream> {
        self.listener
            .accept()
            .await
            .map(|(stream, _address)| stream)
    }
}

#[cfg(windows)]
pub(crate) struct LocalListener {
    pipe_name: String,
    current: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
impl LocalListener {
    pub(crate) fn bind(
        _artifacts: &RuntimeArtifacts,
        runtime_id: &str,
    ) -> Result<(Self, LocalEndpointDescriptor), DaemonError> {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(r"\\.\pipe\rift-{runtime_id}");
        let current = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .map_err(|source| io_error("bind Windows IPC named pipe", source))?;
        Ok((
            Self {
                pipe_name: pipe_name.clone(),
                current,
            },
            LocalEndpointDescriptor {
                transport: LocalTransport::NamedPipe,
                address: pipe_name,
            },
        ))
    }

    pub(crate) async fn accept(&mut self) -> io::Result<LocalStream> {
        use tokio::net::windows::named_pipe::ServerOptions;

        self.current.connect().await?;
        let replacement = ServerOptions::new().create(&self.pipe_name)?;
        Ok(std::mem::replace(&mut self.current, replacement))
    }
}

fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<(), DaemonError> {
    let file_name = path.file_name().and_then(|name| name.to_str()).ok_or(
        DaemonError::InvalidDataDirectory("runtime descriptor path has no UTF-8 file name"),
    )?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary_path = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    ));
    let mut cleanup = TemporaryCleanup::new(temporary_path.clone());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary_path)
        .map_err(|source| io_error("create runtime descriptor temporary file", source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write runtime descriptor", source))?;
    file.flush()
        .map_err(|source| io_error("flush runtime descriptor", source))?;
    file.sync_all()
        .map_err(|source| io_error("sync runtime descriptor", source))?;
    apply_file_permissions(&temporary_path)?;
    verify_file_permissions(&temporary_path)?;
    drop(file);
    fs::rename(&temporary_path, path)
        .map_err(|source| io_error("publish runtime descriptor", source))?;
    cleanup.disarm();
    sync_parent(path)?;
    verify_file_permissions(path)
}

struct TemporaryCleanup {
    path: Option<PathBuf>,
}

impl TemporaryCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TemporaryCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            drop(fs::remove_file(path));
        }
    }
}

fn remove_if_present(path: &Path, operation: &'static str) -> Result<(), DaemonError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(operation, source)),
    }
}

#[cfg(unix)]
fn apply_directory_permissions(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("set data directory permissions", source))
}

#[cfg(not(unix))]
fn apply_directory_permissions(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn verify_directory_permissions(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| io_error("inspect data directory permissions", source))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(DaemonError::InsecurePermissions {
            path: path.to_path_buf(),
            actual: mode,
            expected: 0o700,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_directory_permissions(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn apply_file_permissions(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("set private file permissions", source))
}

#[cfg(not(unix))]
fn apply_file_permissions(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn verify_file_permissions(path: &Path) -> Result<(), DaemonError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|source| io_error("inspect private file permissions", source))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(DaemonError::InsecurePermissions {
            path: path.to_path_buf(),
            actual: mode,
            expected: 0o600,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_file_permissions(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or(DaemonError::InvalidDataDirectory(
        "runtime descriptor has no parent directory",
    ))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("sync runtime directory", source))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), DaemonError> {
    Ok(())
}

#[cfg(target_os = "linux")]
const fn unix_socket_path_max() -> usize {
    107
}

#[cfg(all(unix, not(target_os = "linux")))]
const fn unix_socket_path_max() -> usize {
    103
}

fn io_error(operation: &'static str, source: io::Error) -> DaemonError {
    DaemonError::Io { operation, source }
}
