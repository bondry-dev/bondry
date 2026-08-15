use std::fmt;

use thiserror::Error;

use crate::NetworkEndpoint;

/// Maximum number of additional roots carried by one route.
pub const MAX_ADDITIONAL_TRUST_ANCHORS: usize = 8;
/// Maximum DER size for one additional root.
pub const MAX_ADDITIONAL_TRUST_ANCHOR_BYTES: usize = 16 * 1024;
/// Maximum aggregate DER size for a route's additional roots.
pub const MAX_ADDITIONAL_TRUST_ANCHOR_AGGREGATE_BYTES: usize = 64 * 1024;

/// DER-encoded root certificate added for one route.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct AdditionalTrustAnchor(Vec<u8>);

impl AdditionalTrustAnchor {
    /// Wraps an additional root certificate for transport validation.
    pub fn from_der(der: Vec<u8>) -> Result<Self, TrustAnchorError> {
        if der.is_empty() {
            return Err(TrustAnchorError::Empty);
        }
        if der.len() > MAX_ADDITIONAL_TRUST_ANCHOR_BYTES {
            return Err(TrustAnchorError::TooLong);
        }
        Ok(Self(der))
    }

    /// Returns the DER bytes consumed by a TLS implementation.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// An invalid additional trust anchor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TrustAnchorError {
    /// An empty value cannot encode a certificate.
    #[error("an additional trust anchor cannot be empty")]
    Empty,
    /// One DER value exceeds the route limit.
    #[error("an additional trust anchor cannot exceed 16 KiB")]
    TooLong,
}

impl fmt::Debug for AdditionalTrustAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdditionalTrustAnchor")
            .field("der", &"[REDACTED]")
            .finish()
    }
}

/// Redirect behavior for network transports.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RedirectPolicy {
    /// Never follow a redirect.
    #[default]
    Deny,
}

/// Route-owned network policy enforced against the established connection.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct EndpointPolicy {
    allow_hostname_loopback_cleartext: bool,
    allow_private_cleartext: bool,
    allow_link_local_cleartext: bool,
    redirects: RedirectPolicy,
    additional_trust_anchors: Vec<AdditionalTrustAnchor>,
}

impl EndpointPolicy {
    /// Explicitly permits a hostname to resolve to a verified loopback peer.
    #[must_use]
    pub const fn allowing_hostname_loopback_cleartext(mut self) -> Self {
        self.allow_hostname_loopback_cleartext = true;
        self
    }

    /// Explicitly permits cleartext connections to RFC 1918 and IPv6 ULA peers.
    #[must_use]
    pub const fn allowing_private_cleartext(mut self) -> Self {
        self.allow_private_cleartext = true;
        self
    }

    /// Explicitly permits scoped cleartext connections to link-local peers.
    #[must_use]
    pub const fn allowing_link_local_cleartext(mut self) -> Self {
        self.allow_link_local_cleartext = true;
        self
    }

    /// Returns whether a hostname may connect to a verified loopback peer over cleartext.
    #[must_use]
    pub const fn allows_hostname_loopback_cleartext(&self) -> bool {
        self.allow_hostname_loopback_cleartext
    }

    /// Returns whether verified private-network peers may use cleartext.
    #[must_use]
    pub const fn allows_private_cleartext(&self) -> bool {
        self.allow_private_cleartext
    }

    /// Returns whether verified scoped link-local peers may use cleartext.
    #[must_use]
    pub const fn allows_link_local_cleartext(&self) -> bool {
        self.allow_link_local_cleartext
    }

    /// Adds a root without changing any other certificate verification rule.
    pub fn with_additional_trust_anchor(
        mut self,
        anchor: AdditionalTrustAnchor,
    ) -> Result<Self, EndpointPolicyError> {
        if self.additional_trust_anchors.len() == MAX_ADDITIONAL_TRUST_ANCHORS {
            return Err(EndpointPolicyError::TooManyTrustAnchors);
        }
        let aggregate_bytes = self
            .additional_trust_anchors
            .iter()
            .map(|existing| existing.as_der().len())
            .sum::<usize>();
        if aggregate_bytes + anchor.as_der().len() > MAX_ADDITIONAL_TRUST_ANCHOR_AGGREGATE_BYTES {
            return Err(EndpointPolicyError::TrustAnchorsTooLarge);
        }
        self.additional_trust_anchors.push(anchor);
        Ok(self)
    }

    /// Returns the additional route roots.
    #[must_use]
    pub fn additional_trust_anchors(&self) -> &[AdditionalTrustAnchor] {
        &self.additional_trust_anchors
    }

    /// Returns the redirect policy, which is deny-only in 0.2.0.
    #[must_use]
    pub const fn redirects(&self) -> RedirectPolicy {
        self.redirects
    }

    /// Verifies evidence from the connection that will carry application bytes.
    pub fn verify_connection(
        &self,
        endpoint: &NetworkEndpoint,
        evidence: ConnectionEvidence,
    ) -> Result<VerifiedConnection, PolicyError> {
        if endpoint.scheme().requires_tls() {
            let ConnectionEvidence::Tls(tls) = &evidence else {
                return Err(match evidence {
                    ConnectionEvidence::Missing => PolicyError::MissingEvidence,
                    _ => PolicyError::EvidenceMismatch,
                });
            };
            if !server_names_match(endpoint.host(), tls.server_name()) {
                return Err(PolicyError::TlsIdentityMismatch);
            }
            return Ok(VerifiedConnection { evidence });
        }

        let ConnectionEvidence::Cleartext(peer) = &evidence else {
            return Err(match evidence {
                ConnectionEvidence::Missing => PolicyError::MissingEvidence,
                _ => PolicyError::EvidenceMismatch,
            });
        };
        if peer.port() != endpoint.port() {
            return Err(PolicyError::EvidenceMismatch);
        }
        match classify_ip(peer.ip()) {
            IpAddressClass::Loopback if loopback_intent(endpoint.host()) => {
                Ok(VerifiedConnection { evidence })
            }
            IpAddressClass::Loopback
                if self.allow_hostname_loopback_cleartext
                    && !looks_like_ip_literal(endpoint.host()) =>
            {
                Ok(VerifiedConnection { evidence })
            }
            IpAddressClass::Loopback => Err(PolicyError::LoopbackIntentRequired),
            IpAddressClass::Private if self.allow_private_cleartext => {
                Ok(VerifiedConnection { evidence })
            }
            IpAddressClass::Private => Err(PolicyError::PrivateCleartextDenied),
            IpAddressClass::LinkLocal
                if self.allow_link_local_cleartext && peer.interface_scope().is_some() =>
            {
                Ok(VerifiedConnection { evidence })
            }
            IpAddressClass::LinkLocal if self.allow_link_local_cleartext => {
                Err(PolicyError::LinkLocalScopeRequired)
            }
            IpAddressClass::LinkLocal => Err(PolicyError::LinkLocalCleartextDenied),
            _ => Err(PolicyError::CleartextDenied),
        }
    }

    /// Rejects redirects before any connection to the new target is attempted.
    pub const fn verify_redirect(&self, _target: &NetworkEndpoint) -> Result<(), PolicyError> {
        Err(PolicyError::RedirectDenied)
    }
}

/// An invalid route-owned endpoint policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EndpointPolicyError {
    /// The route exceeds the trust-anchor count limit.
    #[error("an endpoint policy cannot contain more than 8 additional trust anchors")]
    TooManyTrustAnchors,
    /// The route exceeds the aggregate trust-anchor size limit.
    #[error("an endpoint policy cannot contain more than 64 KiB of additional trust anchors")]
    TrustAnchorsTooLarge,
}

/// An IP address represented without socket APIs in the contract layer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IpAddress {
    /// Four IPv4 octets in network order.
    V4([u8; 4]),
    /// Sixteen IPv6 octets in network order.
    V6([u8; 16]),
}

impl IpAddress {
    /// Converts an IPv4-mapped IPv6 address to IPv4 before classification.
    #[must_use]
    pub const fn normalized(self) -> Self {
        match self {
            Self::V6(bytes)
                if bytes[0] == 0
                    && bytes[1] == 0
                    && bytes[2] == 0
                    && bytes[3] == 0
                    && bytes[4] == 0
                    && bytes[5] == 0
                    && bytes[6] == 0
                    && bytes[7] == 0
                    && bytes[8] == 0
                    && bytes[9] == 0
                    && bytes[10] == 0xff
                    && bytes[11] == 0xff =>
            {
                Self::V4([bytes[12], bytes[13], bytes[14], bytes[15]])
            }
            _ => self,
        }
    }
}

/// Security-relevant address classes from the endpoint policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpAddressClass {
    /// IPv4 127/8 or IPv6 ::1.
    Loopback,
    /// RFC 1918 or IPv6 ULA.
    Private,
    /// IPv4 169.254/16 or IPv6 fe80::/10.
    LinkLocal,
    /// IPv4 100.64/10.
    CarrierGradeNat,
    /// The all-zero address.
    Unspecified,
    /// IPv4 or IPv6 multicast.
    Multicast,
    /// A documentation-only prefix.
    Documentation,
    /// Benchmark, protocol-reserved, or otherwise non-public space.
    Reserved,
    /// Globally routed unicast space.
    Public,
}

/// Classifies a normalized actual peer address for cleartext policy.
#[must_use]
pub fn classify_ip(address: IpAddress) -> IpAddressClass {
    match address.normalized() {
        IpAddress::V4(bytes) => classify_ipv4(bytes),
        IpAddress::V6(bytes) => classify_ipv6(bytes),
    }
}

/// The actual connected peer reported by an implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerAddress {
    ip: IpAddress,
    port: u16,
    interface_scope: Option<u32>,
}

impl PeerAddress {
    /// Records the peer with no interface scope.
    #[must_use]
    pub const fn new(ip: IpAddress, port: u16) -> Self {
        Self {
            ip,
            port,
            interface_scope: None,
        }
    }

    /// Records a nonzero interface scope for a link-local peer.
    #[must_use]
    pub const fn with_interface_scope(mut self, interface_scope: u32) -> Self {
        if interface_scope != 0 {
            self.interface_scope = Some(interface_scope);
        }
        self
    }

    /// Returns the normalized peer address.
    #[must_use]
    pub const fn ip(&self) -> IpAddress {
        self.ip.normalized()
    }

    /// Returns the connected port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the explicit interface scope.
    #[must_use]
    pub const fn interface_scope(&self) -> Option<u32> {
        self.interface_scope
    }
}

/// Evidence produced after an authenticated TLS handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsConnectionEvidence {
    server_name: String,
}

impl TlsConnectionEvidence {
    /// Records the identity checked by the TLS implementation.
    #[must_use]
    pub fn verified(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
        }
    }

    /// Returns the authenticated server name.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

/// Connection-time evidence supplied by a transport implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionEvidence {
    /// No usable evidence was supplied; policy always rejects this variant.
    Missing,
    /// Authenticated TLS identity.
    Tls(TlsConnectionEvidence),
    /// Actual peer for a cleartext connection.
    Cleartext(PeerAddress),
}

/// Connection evidence accepted by the route policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedConnection {
    evidence: ConnectionEvidence,
}

impl VerifiedConnection {
    /// Returns the evidence that passed policy.
    #[must_use]
    pub const fn evidence(&self) -> &ConnectionEvidence {
        &self.evidence
    }
}

/// A stable endpoint-policy rejection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// The host or implementation supplied no connection evidence.
    #[error("verified connection evidence is required")]
    MissingEvidence,
    /// Evidence does not match the endpoint's encryption mode.
    #[error("connection evidence does not match the endpoint")]
    EvidenceMismatch,
    /// TLS authenticated a different identity.
    #[error("authenticated TLS identity does not match the endpoint")]
    TlsIdentityMismatch,
    /// A loopback peer was reached without explicit loopback intent.
    #[error("cleartext loopback requires explicit endpoint intent")]
    LoopbackIntentRequired,
    /// A private cleartext peer requires explicit route opt-in.
    #[error("private-network cleartext is not allowed")]
    PrivateCleartextDenied,
    /// A link-local cleartext peer requires explicit route opt-in.
    #[error("link-local cleartext is not allowed")]
    LinkLocalCleartextDenied,
    /// An opted-in link-local peer still requires an interface scope.
    #[error("link-local cleartext requires an interface scope")]
    LinkLocalScopeRequired,
    /// The cleartext peer is never eligible.
    #[error("cleartext is not allowed for this peer")]
    CleartextDenied,
    /// Redirects are disabled in 0.2.0.
    #[error("redirects are disabled")]
    RedirectDenied,
}

fn classify_ipv4(bytes: [u8; 4]) -> IpAddressClass {
    if bytes[0] == 127 {
        return IpAddressClass::Loopback;
    }
    if bytes == [0, 0, 0, 0] {
        return IpAddressClass::Unspecified;
    }
    if bytes[0] == 10
        || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
        || (bytes[0] == 192 && bytes[1] == 168)
    {
        return IpAddressClass::Private;
    }
    if bytes[0] == 169 && bytes[1] == 254 {
        return IpAddressClass::LinkLocal;
    }
    if bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127 {
        return IpAddressClass::CarrierGradeNat;
    }
    if bytes[0] >= 224 && bytes[0] <= 239 {
        return IpAddressClass::Multicast;
    }
    if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
        || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
        || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
    {
        return IpAddressClass::Documentation;
    }
    if bytes[0] == 0
        || bytes[0] >= 240
        || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)
        || (bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99)
        || (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))
    {
        return IpAddressClass::Reserved;
    }
    IpAddressClass::Public
}

fn classify_ipv6(bytes: [u8; 16]) -> IpAddressClass {
    if bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
        return IpAddressClass::Loopback;
    }
    if bytes == [0; 16] {
        return IpAddressClass::Unspecified;
    }
    if bytes[0] & 0xfe == 0xfc {
        return IpAddressClass::Private;
    }
    if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
        return IpAddressClass::LinkLocal;
    }
    if bytes[0] == 0xff {
        return IpAddressClass::Multicast;
    }
    if (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        || (bytes[0] == 0x3f && bytes[1] == 0xff && bytes[2] & 0xf0 == 0)
    {
        return IpAddressClass::Documentation;
    }
    if bytes[0] & 0xe0 != 0x20
        || (bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] == 0x00 || bytes[2] == 0x02))
    {
        return IpAddressClass::Reserved;
    }
    IpAddressClass::Public
}

fn server_names_match(endpoint: &str, verified: &str) -> bool {
    endpoint
        .trim_end_matches('.')
        .eq_ignore_ascii_case(verified.trim_end_matches('.'))
}

fn loopback_intent(host: &str) -> bool {
    let host = unbracketed_host(host);
    let hostname = host.strip_suffix('.').unwrap_or(host);
    if !hostname.ends_with('.') && hostname.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host == "::1" {
        return true;
    }
    canonical_ipv4(host).is_some_and(|address| address[0] == 127)
}

fn looks_like_ip_literal(host: &str) -> bool {
    let host = unbracketed_host(host);
    host.contains(':')
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn unbracketed_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
}

fn canonical_ipv4(host: &str) -> Option<[u8; 4]> {
    let mut address = [0_u8; 4];
    let mut parts = host.split('.');
    for octet in &mut address {
        let part = parts.next()?;
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    parts.next().is_none().then_some(address)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{
        AdditionalTrustAnchor, ConnectionEvidence, EndpointPolicy, EndpointPolicyError, IpAddress,
        IpAddressClass, MAX_ADDITIONAL_TRUST_ANCHOR_AGGREGATE_BYTES,
        MAX_ADDITIONAL_TRUST_ANCHOR_BYTES, MAX_ADDITIONAL_TRUST_ANCHORS, PeerAddress, PolicyError,
        TlsConnectionEvidence, TrustAnchorError, classify_ip,
    };
    use crate::NetworkEndpoint;

    fn endpoint(value: &str) -> NetworkEndpoint {
        NetworkEndpoint::new(
            value
                .parse()
                .unwrap_or_else(|error| unreachable!("valid URI: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("valid endpoint: {error}"))
    }

    #[derive(Deserialize)]
    struct FixtureBundle {
        host_transport_contract: HostTransportContract,
        vectors: Vec<Fixture>,
    }

    #[derive(Deserialize)]
    struct HostTransportContract {
        policy_enforcement: String,
        missing_evidence: String,
        verified_connection_metadata: String,
        redirects: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        endpoint: String,
        #[serde(default)]
        allow_hostname_loopback_cleartext: bool,
        #[serde(default)]
        allow_private_cleartext: bool,
        #[serde(default)]
        allow_link_local_cleartext: bool,
        evidence: FixtureEvidence,
        expected: String,
    }

    #[derive(Deserialize)]
    struct FixtureEvidence {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        ip: Vec<u8>,
        #[serde(default)]
        port: u16,
        interface_scope: Option<u32>,
        server_name: Option<String>,
    }

    #[test]
    fn reproduces_host_transport_policy_fixtures() {
        let bundle: FixtureBundle = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/transport-v1/policy.json"
        )))
        .unwrap_or_else(|error| unreachable!("valid policy fixtures: {error}"));
        assert_eq!(
            bundle.host_transport_contract.policy_enforcement,
            "established_peer_before_application_bytes"
        );
        assert_eq!(bundle.host_transport_contract.missing_evidence, "reject");
        assert_eq!(
            bundle.host_transport_contract.verified_connection_metadata,
            "required"
        );
        assert_eq!(bundle.host_transport_contract.redirects, "deny");
        for fixture in bundle.vectors {
            let mut policy = EndpointPolicy::default();
            if fixture.allow_hostname_loopback_cleartext {
                policy = policy.allowing_hostname_loopback_cleartext();
            }
            if fixture.allow_private_cleartext {
                policy = policy.allowing_private_cleartext();
            }
            if fixture.allow_link_local_cleartext {
                policy = policy.allowing_link_local_cleartext();
            }
            let evidence = fixture_evidence(fixture.evidence);
            let result = policy.verify_connection(&endpoint(&fixture.endpoint), evidence);
            let actual = match result {
                Ok(_) => "allowed",
                Err(PolicyError::EvidenceMismatch) => "evidenceMismatch",
                Err(PolicyError::PrivateCleartextDenied) => "privateCleartextDenied",
                Err(PolicyError::LinkLocalCleartextDenied) => "linkLocalCleartextDenied",
                Err(PolicyError::LinkLocalScopeRequired) => "linkLocalScopeRequired",
                Err(PolicyError::TlsIdentityMismatch) => "tlsIdentityMismatch",
                Err(PolicyError::LoopbackIntentRequired) => "loopbackIntentRequired",
                Err(PolicyError::MissingEvidence) => "missingEvidence",
                Err(PolicyError::CleartextDenied) => "cleartextDenied",
                Err(error) => unreachable!("unexpected fixture result: {error}"),
            };
            assert_eq!(actual, fixture.expected);
        }
    }

    fn fixture_evidence(fixture: FixtureEvidence) -> ConnectionEvidence {
        match fixture.kind.as_str() {
            "missing" => ConnectionEvidence::Missing,
            "tls" => ConnectionEvidence::Tls(TlsConnectionEvidence::verified(
                fixture.server_name.unwrap_or_default(),
            )),
            "cleartext" => {
                let address = match fixture.ip.as_slice() {
                    [a, b, c, d] => IpAddress::V4([*a, *b, *c, *d]),
                    bytes if bytes.len() == 16 => {
                        let mut address = [0_u8; 16];
                        address.copy_from_slice(bytes);
                        IpAddress::V6(address)
                    }
                    _ => unreachable!("fixture address must contain 4 or 16 bytes"),
                };
                let mut peer = PeerAddress::new(address, fixture.port);
                if let Some(scope) = fixture.interface_scope {
                    peer = peer.with_interface_scope(scope);
                }
                ConnectionEvidence::Cleartext(peer)
            }
            _ => unreachable!("unknown fixture evidence"),
        }
    }

    #[test]
    fn classifies_exact_policy_ranges() {
        let cases = [
            (IpAddress::V4([127, 42, 0, 1]), IpAddressClass::Loopback),
            (
                IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                IpAddressClass::Loopback,
            ),
            (IpAddress::V4([10, 0, 0, 1]), IpAddressClass::Private),
            (IpAddress::V4([172, 31, 255, 255]), IpAddressClass::Private),
            (IpAddress::V4([192, 168, 1, 1]), IpAddressClass::Private),
            (
                IpAddress::V6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                IpAddressClass::Private,
            ),
            (IpAddress::V4([169, 254, 1, 1]), IpAddressClass::LinkLocal),
            (
                IpAddress::V4([100, 64, 0, 1]),
                IpAddressClass::CarrierGradeNat,
            ),
            (IpAddress::V4([192, 0, 2, 1]), IpAddressClass::Documentation),
            (IpAddress::V4([198, 18, 0, 1]), IpAddressClass::Reserved),
            (IpAddress::V4([8, 8, 8, 8]), IpAddressClass::Public),
        ];
        for (address, expected) in cases {
            assert_eq!(classify_ip(address), expected);
        }
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        let mapped = IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]);
        assert_eq!(classify_ip(mapped), IpAddressClass::Loopback);
    }

    #[test]
    fn requires_loopback_intent_and_actual_peer_evidence() {
        let loopback =
            ConnectionEvidence::Cleartext(PeerAddress::new(IpAddress::V4([127, 0, 0, 2]), 80));
        assert_eq!(
            EndpointPolicy::default()
                .verify_connection(&endpoint("http://untrusted.example/path"), loopback.clone()),
            Err(PolicyError::LoopbackIntentRequired)
        );
        assert_eq!(
            EndpointPolicy::default()
                .verify_connection(&endpoint("http://localhost../path"), loopback.clone()),
            Err(PolicyError::LoopbackIntentRequired)
        );
        assert!(
            EndpointPolicy::default()
                .allowing_hostname_loopback_cleartext()
                .verify_connection(&endpoint("http://untrusted.example/path"), loopback.clone())
                .is_ok()
        );
        for target in [
            "http://localhost/path",
            "http://LOCALHOST./path",
            "http://127.42.0.1/path",
            "http://[::1]/path",
        ] {
            assert!(
                EndpointPolicy::default()
                    .verify_connection(&endpoint(target), loopback.clone())
                    .is_ok(),
                "{target}"
            );
        }
        for target in ["http://127.0.0.01/path", "http://8.8.8.8/path"] {
            assert_eq!(
                EndpointPolicy::default()
                    .allowing_hostname_loopback_cleartext()
                    .verify_connection(&endpoint(target), loopback.clone()),
                Err(PolicyError::LoopbackIntentRequired),
                "{target}"
            );
        }
        assert_eq!(
            EndpointPolicy::default().verify_connection(
                &endpoint("http://localhost/path"),
                ConnectionEvidence::Cleartext(PeerAddress::new(
                    IpAddress::V4([203, 0, 113, 1]),
                    80,
                ))
            ),
            Err(PolicyError::CleartextDenied)
        );
        assert_eq!(
            EndpointPolicy::default().verify_connection(
                &endpoint("http://localhost:8080/path"),
                ConnectionEvidence::Cleartext(PeerAddress::new(IpAddress::V4([127, 0, 0, 1]), 80,))
            ),
            Err(PolicyError::EvidenceMismatch)
        );
    }

    #[test]
    fn enforces_additional_trust_anchor_bounds() {
        assert_eq!(
            AdditionalTrustAnchor::from_der(Vec::new()),
            Err(TrustAnchorError::Empty)
        );
        assert_eq!(
            AdditionalTrustAnchor::from_der(vec![0; MAX_ADDITIONAL_TRUST_ANCHOR_BYTES + 1]),
            Err(TrustAnchorError::TooLong)
        );

        let anchor = || {
            AdditionalTrustAnchor::from_der(vec![0; MAX_ADDITIONAL_TRUST_ANCHOR_BYTES])
                .unwrap_or_else(|error| unreachable!("bounded fixture: {error}"))
        };
        let mut policy = EndpointPolicy::default();
        for _ in 0..MAX_ADDITIONAL_TRUST_ANCHOR_AGGREGATE_BYTES / MAX_ADDITIONAL_TRUST_ANCHOR_BYTES
        {
            policy = policy
                .with_additional_trust_anchor(anchor())
                .unwrap_or_else(|error| unreachable!("bounded fixture policy: {error}"));
        }
        assert_eq!(
            policy.with_additional_trust_anchor(anchor()),
            Err(EndpointPolicyError::TrustAnchorsTooLarge)
        );

        let mut policy = EndpointPolicy::default();
        for _ in 0..MAX_ADDITIONAL_TRUST_ANCHORS {
            policy = policy
                .with_additional_trust_anchor(
                    AdditionalTrustAnchor::from_der(vec![1])
                        .unwrap_or_else(|error| unreachable!("bounded fixture: {error}")),
                )
                .unwrap_or_else(|error| unreachable!("bounded fixture policy: {error}"));
        }
        assert_eq!(
            policy.with_additional_trust_anchor(
                AdditionalTrustAnchor::from_der(vec![1])
                    .unwrap_or_else(|error| unreachable!("bounded fixture: {error}"))
            ),
            Err(EndpointPolicyError::TooManyTrustAnchors)
        );
    }

    #[test]
    fn private_and_link_local_require_explicit_opt_in() {
        let private = || {
            ConnectionEvidence::Cleartext(PeerAddress::new(IpAddress::V4([192, 168, 1, 10]), 80))
        };
        assert_eq!(
            EndpointPolicy::default().verify_connection(&endpoint("http://home.local"), private()),
            Err(PolicyError::PrivateCleartextDenied)
        );
        assert!(
            EndpointPolicy::default()
                .allowing_private_cleartext()
                .verify_connection(&endpoint("http://home.local"), private())
                .is_ok()
        );

        let unscoped = ConnectionEvidence::Cleartext(PeerAddress::new(
            IpAddress::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            80,
        ));
        assert_eq!(
            EndpointPolicy::default()
                .allowing_link_local_cleartext()
                .verify_connection(&endpoint("http://link.local"), unscoped),
            Err(PolicyError::LinkLocalScopeRequired)
        );
    }

    #[test]
    fn tls_requires_matching_verified_identity() {
        let policy = EndpointPolicy::default();
        let target = endpoint("https://Example.COM/path");
        assert!(
            policy
                .verify_connection(
                    &target,
                    ConnectionEvidence::Tls(TlsConnectionEvidence::verified("example.com"))
                )
                .is_ok()
        );
        assert_eq!(
            policy.verify_connection(
                &target,
                ConnectionEvidence::Tls(TlsConnectionEvidence::verified("other.example"))
            ),
            Err(PolicyError::TlsIdentityMismatch)
        );
        assert_eq!(
            policy.verify_connection(&target, ConnectionEvidence::Missing),
            Err(PolicyError::MissingEvidence)
        );
    }

    #[test]
    fn redirects_are_disabled() {
        assert_eq!(
            EndpointPolicy::default().verify_redirect(&endpoint("https://example.com/next")),
            Err(PolicyError::RedirectDenied)
        );
    }
}
