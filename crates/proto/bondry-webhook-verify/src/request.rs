use http::{HeaderName, Method};

/// Connected peer metadata copied from the server boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAddress {
    family: u8,
    bytes: [u8; 16],
    port: u16,
    interface_scope: Option<u32>,
}

impl PeerAddress {
    /// Creates an IPv4 peer from network-order octets.
    #[must_use]
    pub const fn v4(bytes: [u8; 4], port: u16) -> Self {
        let mut address = [0; 16];
        address[0] = bytes[0];
        address[1] = bytes[1];
        address[2] = bytes[2];
        address[3] = bytes[3];
        Self {
            family: 4,
            bytes: address,
            port,
            interface_scope: None,
        }
    }

    /// Creates an IPv6 peer from network-order octets and optional interface scope.
    #[must_use]
    pub const fn v6(bytes: [u8; 16], port: u16, interface_scope: Option<u32>) -> Self {
        Self {
            family: 6,
            bytes,
            port,
            interface_scope,
        }
    }

    /// Returns four or six.
    #[must_use]
    pub const fn family(self) -> u8 {
        self.family
    }

    /// Returns network-order address bytes; IPv4 uses the first four bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Returns the connected peer port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Returns the IPv6 interface scope when present.
    #[must_use]
    pub const fn interface_scope(self) -> Option<u32> {
        self.interface_scope
    }
}

/// One selected request header preserving exact value bytes and duplicates.
#[derive(Clone)]
pub struct VerificationHeader<'a> {
    name: HeaderName,
    value: &'a [u8],
}

impl<'a> VerificationHeader<'a> {
    /// Creates one callback-scoped selected header.
    #[must_use]
    pub const fn new(name: HeaderName, value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Returns the normalized header name.
    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns exact header value bytes.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Bounded data available to a route-specific verifier.
#[derive(Clone, Copy)]
pub struct VerificationRequest<'a> {
    method: &'a Method,
    target: &'a str,
    headers: &'a [VerificationHeader<'a>],
    body: &'a [u8],
    peer: PeerAddress,
}

impl<'a> VerificationRequest<'a> {
    /// Creates one callback-scoped verification request.
    #[must_use]
    pub const fn new(
        method: &'a Method,
        target: &'a str,
        headers: &'a [VerificationHeader<'a>],
        body: &'a [u8],
        peer: PeerAddress,
    ) -> Self {
        Self {
            method,
            target,
            headers,
            body,
            peer,
        }
    }

    /// Returns the exact accepted method.
    #[must_use]
    pub const fn method(self) -> &'a Method {
        self.method
    }

    /// Returns the exact request target supplied by the server seam.
    #[must_use]
    pub const fn target(self) -> &'a str {
        self.target
    }

    /// Returns selected headers preserving duplicates.
    #[must_use]
    pub const fn headers(self) -> &'a [VerificationHeader<'a>] {
        self.headers
    }

    /// Returns the exact bounded raw body.
    #[must_use]
    pub const fn body(self) -> &'a [u8] {
        self.body
    }

    /// Returns copied connected-peer metadata.
    #[must_use]
    pub const fn peer(self) -> PeerAddress {
        self.peer
    }

    /// Returns every value for one normalized selected header.
    pub fn header_values<'b>(
        &'b self,
        name: &'b HeaderName,
    ) -> impl Iterator<Item = &'a [u8]> + 'b {
        self.headers
            .iter()
            .filter(move |header| header.name() == name)
            .map(VerificationHeader::value)
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderName, Method};

    use super::{PeerAddress, VerificationHeader, VerificationRequest};

    #[test]
    fn preserves_exact_selected_header_values_and_duplicates() {
        let method = Method::POST;
        let signature = HeaderName::from_static("x-signature");
        let headers = [
            VerificationHeader::new(signature.clone(), b"first"),
            VerificationHeader::new(signature.clone(), b"second"),
        ];
        let peer = PeerAddress::v6(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            443,
            Some(4),
        );
        let request =
            VerificationRequest::new(&method, "/hook?exact=1", &headers, b"raw\0body", peer);

        assert_eq!(request.method(), &Method::POST);
        assert_eq!(request.target(), "/hook?exact=1");
        assert_eq!(request.body(), b"raw\0body");
        assert_eq!(
            request.header_values(&signature).collect::<Vec<_>>(),
            [b"first".as_slice(), b"second".as_slice()]
        );
        assert_eq!(request.peer().family(), 6);
        assert_eq!(request.peer().interface_scope(), Some(4));
    }
}
