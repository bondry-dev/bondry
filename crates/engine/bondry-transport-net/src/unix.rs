use std::{
    io::ErrorKind,
    os::fd::AsRawFd,
    os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    path::Path,
    sync::Arc,
};

use bondry_transport::{
    Deadline, LocalByteStream, LocalByteStreamTransport, LocalConnection, LocalEndpoint,
    LocalEndpointPolicy, LocalPeerEvidence, LocalTransportError, TransportFuture,
};
use bytes::Bytes;
use nix::{
    errno::Errno,
    sys::socket::{Shutdown, shutdown},
};
use tokio::{
    net::UnixStream,
    sync::Mutex,
    time::{Instant, timeout_at},
};

const READ_BUFFER_BYTES: usize = 64 * 1024;

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
    stream: UnixStream,
    reader: Mutex<()>,
    writer: Mutex<()>,
}

impl TokioUnixStream {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            reader: Mutex::new(()),
            writer: Mutex::new(()),
        }
    }
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
            let mut buffer = vec![0_u8; max_bytes.min(READ_BUFFER_BYTES)];
            let read = timeout_at(Instant::from_std(deadline.instant()), async {
                let _reader = self.reader.lock().await;
                loop {
                    self.stream
                        .readable()
                        .await
                        .map_err(|_| LocalTransportError::Unavailable)?;
                    match self.stream.try_read(&mut buffer) {
                        Ok(read) => return Ok(read),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => return Err(LocalTransportError::Unavailable),
                    }
                }
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
                let _writer = self.writer.lock().await;
                let mut remaining = bytes.as_ref();
                while !remaining.is_empty() {
                    self.stream
                        .writable()
                        .await
                        .map_err(|_| LocalTransportError::Unavailable)?;
                    match self.stream.try_write(remaining) {
                        Ok(0) => return Err(LocalTransportError::Unavailable),
                        Ok(written) => remaining = &remaining[written..],
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => return Err(LocalTransportError::Unavailable),
                    }
                }
                Ok(())
            })
            .await
            .map_err(|_| LocalTransportError::DeadlineExceeded)?
        })
    }

    fn close(&self) -> TransportFuture<'_, Result<(), LocalTransportError>> {
        Box::pin(async move {
            match shutdown(self.stream.as_raw_fd(), Shutdown::Both) {
                Ok(()) | Err(Errno::ENOTCONN) => Ok(()),
                Err(_) => Err(LocalTransportError::Unavailable),
            }
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
        stream: Arc::new(TokioUnixStream::new(stream)),
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

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        task::Poll,
        time::{Duration, Instant as StdInstant},
    };

    use bondry_transport::{Deadline, LocalByteStream as _};
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        time::timeout,
    };

    use super::{TokioUnixStream, UnixStream};

    #[tokio::test]
    async fn caller_read_bound_cannot_force_an_unbounded_allocation() {
        let (stream, mut peer) = UnixStream::pair()
            .unwrap_or_else(|error| unreachable!("create Unix stream pair: {error}"));
        peer.write_all(b"bounded")
            .await
            .unwrap_or_else(|error| unreachable!("write fixture bytes: {error}"));
        let stream = TokioUnixStream::new(stream);

        let bytes = stream
            .read(
                usize::MAX,
                Deadline::at(StdInstant::now() + Duration::from_secs(1)),
            )
            .await
            .unwrap_or_else(|error| unreachable!("read fixture bytes: {error}"));

        assert_eq!(bytes, b"bounded".as_slice());
    }

    #[tokio::test]
    async fn pending_read_allows_concurrent_write() -> Result<(), Box<dyn std::error::Error>> {
        let (stream, mut peer) = UnixStream::pair()?;
        let stream = TokioUnixStream::new(stream);
        let deadline = Deadline::at(StdInstant::now() + Duration::from_secs(1));
        let mut read = stream.read(4, deadline);
        assert!(
            poll_fn(|context| Poll::Ready(read.as_mut().poll(context)))
                .await
                .is_pending()
        );

        stream.write(Bytes::from_static(b"ping"), deadline).await?;
        let mut request = [0; 4];
        timeout(Duration::from_secs(1), peer.read_exact(&mut request)).await??;
        assert_eq!(&request, b"ping");
        peer.write_all(b"pong").await?;
        assert_eq!(read.await?, b"pong".as_slice());
        Ok(())
    }

    #[tokio::test]
    async fn close_interrupts_pending_read() -> Result<(), Box<dyn std::error::Error>> {
        let (stream, mut peer) = UnixStream::pair()?;
        let stream = TokioUnixStream::new(stream);
        let deadline = Deadline::at(StdInstant::now() + Duration::from_secs(1));
        let mut read = stream.read(1, deadline);
        assert!(
            poll_fn(|context| Poll::Ready(read.as_mut().poll(context)))
                .await
                .is_pending()
        );

        timeout(Duration::from_secs(1), stream.close()).await??;
        assert!(read.await?.is_empty());
        let mut buffer = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read(&mut buffer)).await??,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn close_interrupts_backpressured_write() -> Result<(), Box<dyn std::error::Error>> {
        let (stream, _peer) = UnixStream::pair()?;
        let buffer = [0; 64 * 1024];
        loop {
            match stream.try_write(&buffer) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let stream = TokioUnixStream::new(stream);
        let deadline = Deadline::at(StdInstant::now() + Duration::from_secs(1));
        let mut write = stream.write(Bytes::from_static(b"blocked"), deadline);
        assert!(
            poll_fn(|context| Poll::Ready(write.as_mut().poll(context)))
                .await
                .is_pending()
        );

        timeout(Duration::from_secs(1), stream.close()).await??;
        assert_eq!(
            write.await,
            Err(bondry_transport::LocalTransportError::Unavailable)
        );
        Ok(())
    }

    #[tokio::test]
    async fn close_is_repeatable_and_prevents_later_io() -> Result<(), Box<dyn std::error::Error>> {
        use bondry_transport::LocalTransportError;

        let (stream, _peer) = UnixStream::pair()?;
        let stream = TokioUnixStream::new(stream);
        stream.close().await?;
        stream.close().await?;
        let deadline = Deadline::at(StdInstant::now() + Duration::from_secs(1));
        assert!(stream.read(1, deadline).await?.is_empty());
        assert_eq!(
            stream.write(Bytes::from_static(b"closed"), deadline).await,
            Err(LocalTransportError::Unavailable)
        );
        assert_eq!(
            stream.read(0, deadline).await,
            Err(LocalTransportError::InvalidReadBound)
        );
        Ok(())
    }
}
