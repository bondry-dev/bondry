#![doc = "End-to-end transport verification."]

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
        sync::Arc,
        time::{Duration, Instant},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use bondry_transport::{
        AdditionalTrustAnchor, ConnectionEvidence, Deadline, EndpointPolicy, HttpLimits,
        HttpRequest, HttpTransport as _, LocalByteStreamTransport as _, LocalEndpoint,
        LocalEndpointPolicy, LocalTransportError, NetworkEndpoint, TransportError,
        UnixSocketPolicy,
    };
    use bondry_transport_net::{NetHttpTransport, UnixSocketTransport};
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde::Deserialize;
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
        net::{TcpListener, UnixListener},
    };
    use tokio_rustls::TlsAcceptor;

    #[tokio::test(flavor = "current_thread")]
    async fn cleartext_loopback_uses_actual_peer_and_refuses_redirects()
    -> Result<(), Box<dyn Error>> {
        let (port, server) =
            http_server(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
        let transport = NetHttpTransport::new()?;
        let response = transport
            .send(request(
                &format!("http://localhost:{port}/accepted"),
                EndpointPolicy::default(),
            )?)
            .await?;
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        assert!(matches!(
            response.connection().evidence(),
            ConnectionEvidence::Cleartext(_)
        ));
        server.await??;

        let (port, server) = http_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/next\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        let result = transport
            .send(request(
                &format!("http://localhost:{port}/redirect"),
                EndpointPolicy::default(),
            )?)
            .await;
        assert_eq!(
            result.err(),
            Some(TransportError::Policy(
                bondry_transport::PolicyError::RedirectDenied
            ))
        );
        server.await??;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn additional_anchor_adds_trust_without_disabling_identity() -> Result<(), Box<dyn Error>>
    {
        let certificate = test_certificate()?;
        let (port, server) = tls_server(&certificate).await?;
        let transport = NetHttpTransport::new()?;
        let rejected = transport
            .send(request(
                &format!("https://localhost:{port}/default"),
                EndpointPolicy::default(),
            )?)
            .await;
        assert_eq!(rejected.err(), Some(TransportError::TlsFailed));
        let _ = server.await?;

        let (port, server) = tls_server(&certificate).await?;
        let policy = EndpointPolicy::default().with_additional_trust_anchor(
            AdditionalTrustAnchor::from_der(certificate.root.clone()),
        );
        let response = transport
            .send(request(
                &format!("https://localhost:{port}/trusted"),
                policy.clone(),
            )?)
            .await?;
        assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
        server.await??;

        let (port, server) = tls_server(&certificate).await?;
        let wrong_identity = transport
            .send(request(
                &format!("https://127.0.0.1:{port}/wrong-name"),
                policy,
            )?)
            .await;
        assert_eq!(wrong_identity.err(), Some(TransportError::TlsFailed));
        let _ = server.await?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unix_socket_enforces_mode_owner_and_peer_then_round_trips()
    -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("bondry.sock");
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::metadata(&path)?;
        let policy = UnixSocketPolicy::new(metadata.uid(), 0o077, metadata.uid())
            .requiring_owner_group(metadata.gid());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await?;
            stream.write_all(b"pong").await?;
            Ok::<_, std::io::Error>(request)
        });

        let connection = UnixSocketTransport
            .connect(
                LocalEndpoint::Unix(path.clone()),
                LocalEndpointPolicy::Unix(policy),
                deadline(),
            )
            .await?;
        connection
            .stream
            .write(Bytes::from_static(b"ping"), deadline())
            .await?;
        assert_eq!(connection.stream.read(4, deadline()).await?, b"pong"[..]);
        assert_eq!(server.await??, *b"ping");

        let listener = UnixListener::bind(directory.path().join("open.sock"))?;
        let open_path = directory.path().join("open.sock");
        fs::set_permissions(&open_path, fs::Permissions::from_mode(0o666))?;
        let result = UnixSocketTransport
            .connect(
                LocalEndpoint::Unix(open_path),
                LocalEndpointPolicy::Unix(policy),
                deadline(),
            )
            .await;
        assert!(matches!(result, Err(LocalTransportError::ModeRejected)));
        drop(listener);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_shared_malformed_http_responses() -> Result<(), Box<dyn Error>> {
        let bundle: MalformedBundle = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/transport-v1/malformed-http1.json"
        )))?;
        let transport = NetHttpTransport::new()?;
        for vector in bundle.vectors {
            let raw = STANDARD.decode(vector.response_base64)?;
            let (port, server) = http_server(&raw).await?;
            let result = transport
                .send(request(
                    &format!("http://localhost:{port}/malformed"),
                    EndpointPolicy::default(),
                )?)
                .await;
            assert_eq!(
                result.err(),
                Some(TransportError::InvalidResponse),
                "{}",
                vector.id
            );
            server.await??;
        }
        Ok(())
    }

    #[derive(Deserialize)]
    struct MalformedBundle {
        vectors: Vec<MalformedVector>,
    }

    #[derive(Deserialize)]
    struct MalformedVector {
        id: String,
        response_base64: String,
    }

    fn request(endpoint: &str, policy: EndpointPolicy) -> Result<HttpRequest, Box<dyn Error>> {
        Ok(HttpRequest::new(
            Method::GET,
            NetworkEndpoint::new(endpoint.parse()?)?,
            HeaderMap::new(),
            Bytes::new(),
            deadline(),
            policy,
            HttpLimits::default(),
        )?)
    }

    fn deadline() -> Deadline {
        Deadline::at(Instant::now() + Duration::from_secs(5))
    }

    async fn http_server(
        response: &[u8],
    ) -> Result<(u16, tokio::task::JoinHandle<Result<(), std::io::Error>>), std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let response = response.to_vec();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            respond(stream, &response).await
        });
        Ok((port, server))
    }

    struct TestCertificate {
        root: Vec<u8>,
        leaf: Vec<u8>,
        key: Vec<u8>,
    }

    #[derive(Deserialize)]
    struct TlsFixture {
        trust_anchor_der_base64: String,
        server_certificate_der_base64: String,
        private_key_pkcs8_base64: String,
    }

    fn test_certificate() -> Result<TestCertificate, Box<dyn Error>> {
        let fixture: TlsFixture = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/transport-v1/localhost-tls.json"
        )))?;
        Ok(TestCertificate {
            root: STANDARD.decode(fixture.trust_anchor_der_base64)?,
            leaf: STANDARD.decode(fixture.server_certificate_der_base64)?,
            key: STANDARD.decode(fixture.private_key_pkcs8_base64)?,
        })
    }

    async fn tls_server(
        certificate: &TestCertificate,
    ) -> Result<(u16, tokio::task::JoinHandle<Result<(), std::io::Error>>), Box<dyn Error>> {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.leaf.clone().into()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.key.clone())),
            )?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let stream = acceptor
                .accept(stream)
                .await
                .map_err(std::io::Error::other)?;
            respond(
                stream,
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
            )
            .await
        });
        Ok((port, server))
    }

    async fn respond<IO>(mut stream: IO, response: &[u8]) -> Result<(), std::io::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Ok(());
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream.write_all(response).await?;
        stream.shutdown().await
    }
}
