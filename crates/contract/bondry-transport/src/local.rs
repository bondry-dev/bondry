use std::{path::PathBuf, sync::Arc};

use bytes::Bytes;
use thiserror::Error;

use crate::{Deadline, TransportFuture};

/// A local byte-stream endpoint.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LocalEndpoint {
    /// A Unix-domain socket path.
    Unix(PathBuf),
    /// Reserved seat for a future Windows named pipe implementation.
    NamedPipe(String),
}

/// Security requirements for an established Unix-domain socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixSocketPolicy {
    expected_owner_user_id: u32,
    expected_owner_group_id: Option<u32>,
    forbidden_mode_bits: u32,
    expected_peer_user_id: u32,
    expected_peer_group_id: Option<u32>,
}

impl UnixSocketPolicy {
    /// Requires a socket owner, disallowed mode bits, and peer user credential.
    #[must_use]
    pub const fn new(
        expected_owner_user_id: u32,
        forbidden_mode_bits: u32,
        expected_peer_user_id: u32,
    ) -> Self {
        Self {
            expected_owner_user_id,
            expected_owner_group_id: None,
            forbidden_mode_bits,
            expected_peer_user_id,
            expected_peer_group_id: None,
        }
    }

    /// Also requires the filesystem group owner.
    #[must_use]
    pub const fn requiring_owner_group(mut self, group_id: u32) -> Self {
        self.expected_owner_group_id = Some(group_id);
        self
    }

    /// Also requires the connected peer group credential.
    #[must_use]
    pub const fn requiring_peer_group(mut self, group_id: u32) -> Self {
        self.expected_peer_group_id = Some(group_id);
        self
    }

    /// Verifies metadata obtained from the opened socket and connected peer.
    pub fn verify(
        self,
        evidence: LocalPeerEvidence,
    ) -> Result<VerifiedLocalConnection, LocalTransportError> {
        let LocalPeerEvidence::Unix {
            owner_user_id,
            owner_group_id,
            mode,
            peer_user_id,
            peer_group_id,
        } = evidence
        else {
            return Err(LocalTransportError::EvidenceMismatch);
        };
        if owner_user_id != self.expected_owner_user_id
            || self
                .expected_owner_group_id
                .is_some_and(|expected| expected != owner_group_id)
        {
            return Err(LocalTransportError::OwnershipRejected);
        }
        if mode & self.forbidden_mode_bits != 0 {
            return Err(LocalTransportError::ModeRejected);
        }
        if peer_user_id != self.expected_peer_user_id
            || self
                .expected_peer_group_id
                .is_some_and(|expected| Some(expected) != peer_group_id)
        {
            return Err(LocalTransportError::PeerCredentialRejected);
        }
        Ok(VerifiedLocalConnection { evidence })
    }
}

/// Policy paired with a local endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalEndpointPolicy {
    /// Unix socket filesystem and peer requirements.
    Unix(UnixSocketPolicy),
    /// Reserved named-pipe policy seat.
    NamedPipeReserved,
}

/// Metadata captured from the opened local stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPeerEvidence {
    /// Unix socket filesystem metadata and kernel peer credentials.
    Unix {
        /// User owning the opened socket node.
        owner_user_id: u32,
        /// Group owning the opened socket node.
        owner_group_id: u32,
        /// Permission bits from the opened socket node.
        mode: u32,
        /// Effective user credential of the connected peer.
        peer_user_id: u32,
        /// Effective group credential when the platform exposes it.
        peer_group_id: Option<u32>,
    },
    /// Reserved named-pipe evidence seat.
    NamedPipeReserved,
}

/// Local evidence accepted by its endpoint policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedLocalConnection {
    evidence: LocalPeerEvidence,
}

impl VerifiedLocalConnection {
    /// Returns the metadata that passed policy.
    #[must_use]
    pub const fn evidence(self) -> LocalPeerEvidence {
        self.evidence
    }
}

/// An established local stream and its verified peer.
pub struct LocalConnection {
    /// Connected byte stream.
    pub stream: Arc<dyn LocalByteStream>,
    /// Policy-accepted peer evidence.
    pub verified: VerifiedLocalConnection,
}

/// Bounded operations on an established local byte stream.
pub trait LocalByteStream: Send + Sync {
    /// Reads at most `max_bytes` before the deadline.
    fn read(
        &self,
        max_bytes: usize,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<Bytes, LocalTransportError>>;

    /// Writes the complete bounded buffer before the deadline.
    fn write(
        &self,
        bytes: Bytes,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), LocalTransportError>>;

    /// Closes the stream.
    fn close(&self) -> TransportFuture<'_, Result<(), LocalTransportError>>;
}

/// Connects to local byte streams without sharing network-protocol semantics.
pub trait LocalByteStreamTransport: Send + Sync {
    /// Connects and verifies the actual local peer before returning the stream.
    fn connect(
        &self,
        endpoint: LocalEndpoint,
        policy: LocalEndpointPolicy,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<LocalConnection, LocalTransportError>>;
}

/// A stable local-stream failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalTransportError {
    /// The selected local endpoint is not implemented.
    #[error("unsupported local endpoint")]
    UnsupportedEndpoint,
    /// Filesystem or peer evidence is absent or has the wrong kind.
    #[error("local peer evidence does not match the endpoint")]
    EvidenceMismatch,
    /// The socket owner does not match policy.
    #[error("local socket ownership rejected")]
    OwnershipRejected,
    /// Socket permission bits do not match policy.
    #[error("local socket permissions rejected")]
    ModeRejected,
    /// Kernel peer credentials do not match policy.
    #[error("local peer credentials rejected")]
    PeerCredentialRejected,
    /// Connection establishment or byte transfer failed.
    #[error("local transport unavailable")]
    Unavailable,
    /// The operation exceeded its deadline.
    #[error("local transport deadline exceeded")]
    DeadlineExceeded,
    /// A caller supplied an unbounded zero-byte read.
    #[error("local read bound must be nonzero")]
    InvalidReadBound,
}

#[cfg(test)]
mod tests {
    use super::{LocalPeerEvidence, LocalTransportError, UnixSocketPolicy};

    fn evidence(mode: u32, peer_user_id: u32) -> LocalPeerEvidence {
        LocalPeerEvidence::Unix {
            owner_user_id: 501,
            owner_group_id: 20,
            mode,
            peer_user_id,
            peer_group_id: Some(20),
        }
    }

    #[test]
    fn verifies_owner_mode_and_peer_credentials() {
        let policy = UnixSocketPolicy::new(501, 0o022, 501)
            .requiring_owner_group(20)
            .requiring_peer_group(20);
        assert!(policy.verify(evidence(0o777, 501)).is_err());
        assert_eq!(
            policy.verify(evidence(0o700, 502)),
            Err(LocalTransportError::PeerCredentialRejected)
        );
        assert!(policy.verify(evidence(0o700, 501)).is_ok());
    }
}
