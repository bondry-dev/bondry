#![doc = "Default socket, HTTP, TLS, and Unix-stream implementations for Bondry."]

#[cfg(feature = "http")]
mod http;
#[cfg(feature = "unix-socket")]
mod unix;

#[cfg(feature = "http")]
pub use http::{NetHttpTransport, TransportConfigurationError};
#[cfg(feature = "unix-socket")]
pub use unix::UnixSocketTransport;
