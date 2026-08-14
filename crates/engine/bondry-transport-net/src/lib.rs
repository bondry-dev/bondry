#![doc = "Default socket, HTTP, TLS, and Unix-stream implementations for Bondry."]

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "unix-socket")]
mod unix;

#[cfg(feature = "http")]
pub use http::{MAX_HTTP_POOL_PARTITIONS, NetHttpTransport, TransportConfigurationError};
#[cfg(feature = "unix-socket")]
pub use unix::UnixSocketTransport;
