use std::{
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::Path,
    sync::Arc,
};

use bondry_transport::{
    Deadline, LocalByteStream, LocalByteStreamTransport, LocalConnection, LocalEndpoint,
    LocalEndpointPolicy, LocalPeerEvidence, LocalTransportError, TransportFuture,
};
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
    sync::Mutex,
    time::{Instant, timeout_at},
};

/// Unix-domain socket transport with filesystem and kernel peer verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixSocketTransport;

impl LocalByteStreamTransport for UnixSocketTransport {
    fn connect(
        &self,
        endpoint: LocalEndpoint,
        policy: LocalEndpointPolicy,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<LocalConnection, LocalTransportError>> {
        Box::pin(async move {
            let (LocalEndpoint::Unix(path), LocalEndpointPolicy::Unix(policy)) = (endpoint, policy)
            else {
                return Err(LocalTransportError::UnsupportedEndpoint);
            };
            let deadline = Instant::from_std(deadline.instant());
            timeout_at(deadline, connect_unix(&path, policy))
                .await
                .map_err(|_| LocalTransportError::DeadlineExceeded)?
        })
    }
}

struct TokioUnixStream {
    stream: Mutex<UnixStream>,
}

impl LocalByteStream for TokioUnixStream {
    fn read(
        &self,
        max_bytes: usize,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<Bytes, LocalTransportError>> {
        Box::pin(async move {
            if max_bytes == 0 {
                return Err(LocalTransportError::InvalidReadBound);
            }
            let mut buffer = vec![0_u8; max_bytes];
            let read = timeout_at(Instant::from_std(deadline.instant()), async {
                self.stream
                    .lock()
                    .await
                    .read(&mut buffer)
                    .await
                    .map_err(|_| LocalTransportError::Unavailable)
            })
            .await
            .map_err(|_| LocalTransportError::DeadlineExceeded)??;
            buffer.truncate(read);
            Ok(Bytes::from(buffer))
        })
    }

    fn write(
        &self,
        bytes: Bytes,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), LocalTransportError>> {
        Box::pin(async move {
            timeout_at(Instant::from_std(deadline.instant()), async {
                self.stream
                    .lock()
                    .await
                    .write_all(&bytes)
                    .await
                    .map_err(|_| LocalTransportError::Unavailable)
            })
            .await
            .map_err(|_| LocalTransportError::DeadlineExceeded)?
        })
    }

    fn close(&self) -> TransportFuture<'_, Result<(), LocalTransportError>> {
        Box::pin(async move {
            self.stream
                .lock()
                .await
                .shutdown()
                .await
                .map_err(|_| LocalTransportError::Unavailable)
        })
    }
}

async fn connect_unix(
    path: &Path,
    policy: bondry_transport::UnixSocketPolicy,
) -> Result<LocalConnection, LocalTransportError> {
    let before = socket_metadata(path)?;
    let stream = UnixStream::connect(path)
        .await
        .map_err(|_| LocalTransportError::Unavailable)?;
    let after = socket_metadata(path)?;
    if before.device != after.device || before.inode != after.inode {
        return Err(LocalTransportError::EvidenceMismatch);
    }
    let (peer_user_id, peer_group_id) = peer_credentials(&stream)?;
    let evidence = LocalPeerEvidence::Unix {
        owner_user_id: after.owner_user_id,
        owner_group_id: after.owner_group_id,
        mode: after.mode,
        peer_user_id,
        peer_group_id: Some(peer_group_id),
    };
    let verified = policy.verify(evidence)?;
    Ok(LocalConnection {
        stream: Arc::new(TokioUnixStream {
            stream: Mutex::new(stream),
        }),
        verified,
    })
}

struct SocketMetadata {
    device: u64,
    inode: u64,
    owner_user_id: u32,
    owner_group_id: u32,
    mode: u32,
}

fn socket_metadata(path: &Path) -> Result<SocketMetadata, LocalTransportError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| LocalTransportError::Unavailable)?;
    if !metadata.file_type().is_socket() {
        return Err(LocalTransportError::EvidenceMismatch);
    }
    Ok(SocketMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_user_id: metadata.uid(),
        owner_group_id: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_credentials(stream: &UnixStream) -> Result<(u32, u32), LocalTransportError> {
    let (user, group) =
        nix::unistd::getpeereid(stream).map_err(|_| LocalTransportError::PeerCredentialRejected)?;
    Ok((user.as_raw(), group.as_raw()))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_credentials(stream: &UnixStream) -> Result<(u32, u32), LocalTransportError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|_| LocalTransportError::PeerCredentialRejected)?;
    Ok((credentials.uid(), credentials.gid()))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn peer_credentials(_stream: &UnixStream) -> Result<(u32, u32), LocalTransportError> {
    Err(LocalTransportError::UnsupportedEndpoint)
}
