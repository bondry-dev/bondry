#![doc = "End-to-end egress verification."]

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, env, error::Error, sync::Arc, time::Duration};

    use bondry_delivery_store::{DeliveryId, DeliveryOutcome, DeliveryState, RouteId};
    use bondry_egress::{
        PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType, PayloadLimit,
        RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit, RouteRegistry,
    };
    use bondry_egress_runtime::{EgressRuntime, EgressRuntimeLimits, InMemoryDeliveryLog};
    use bondry_egress_webhook::{
        SecretUrlTemplate, UrlTemplateLimits, WebhookDeliveryKind, WebhookLimits,
    };
    use bondry_secrets::{
        BONDRY_WEBHOOK_DELIVERY_ID_HEADER, ResolvedSecret, SecretProvider, SecretProviderError,
        SecretRef, SecretValue,
    };
    use bondry_transport::EndpointPolicy;
    use bondry_transport_net::NetHttpTransport;
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
        task::JoinHandle,
    };

    struct PilotSecrets {
        values: BTreeMap<String, Vec<u8>>,
    }

    impl SecretProvider for PilotSecrets {
        fn resolve(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
            let value = self
                .values
                .get(reference.as_str())
                .ok_or(SecretProviderError::NotFound)?;
            SecretValue::new(value.clone())
                .map(ResolvedSecret::current)
                .map_err(|_| SecretProviderError::InvalidMaterial)
        }
    }

    struct ReceivedRequest {
        target: String,
        delivery_id: String,
        body: Vec<u8>,
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watchdog_publishes_power_loss_and_heartbeat_to_ntfy_contract()
    -> Result<(), Box<dyn Error>> {
        let (port, receiver) = ntfy_receiver(2).await?;
        let secret_values = BTreeMap::from([
            ("topic:alerts".to_owned(), b"pilot-alerts".to_vec()),
            ("topic:heartbeat".to_owned(), b"pilot-heartbeat".to_vec()),
        ]);
        let mut runtime = start_runtime(secret_values)?;
        runtime.register_route(ntfy_route(
            "power-lost",
            format!("http://127.0.0.1:{port}/{{secret}}"),
            SecretRef::new("topic:alerts")?,
        )?)?;
        runtime.register_route(ntfy_route(
            "heartbeat",
            format!("http://127.0.0.1:{port}/{{secret}}"),
            SecretRef::new("topic:heartbeat")?,
        )?)?;

        let summaries = runtime.routes()?;
        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .all(|route| route.target().contains("{secret}"))
        );
        assert!(
            summaries
                .iter()
                .all(|route| !route.target().contains("pilot-"))
        );

        let power_delivery = DeliveryId::new("pilot-power-1")?;
        let heartbeat_delivery = DeliveryId::new("pilot-heartbeat-1")?;
        runtime.emit(
            RouteId::new("power-lost")?,
            power_delivery.clone(),
            Bytes::from_static(br#"{"message":"power lost"}"#),
        )?;
        runtime.emit(
            RouteId::new("heartbeat")?,
            heartbeat_delivery.clone(),
            Bytes::from_static(br#"{"message":"heartbeat"}"#),
        )?;

        wait_for_delivery(&runtime, &power_delivery).await?;
        wait_for_delivery(&runtime, &heartbeat_delivery).await?;
        runtime.stop()?;

        let mut requests = tokio::time::timeout(Duration::from_secs(5), receiver).await???;
        requests.sort_by(|left, right| left.target.cmp(&right.target));
        assert_eq!(requests[0].target, "/pilot-alerts");
        assert_eq!(requests[0].delivery_id, "pilot-power-1");
        assert_eq!(requests[0].body, br#"{"message":"power lost"}"#);
        assert_eq!(requests[1].target, "/pilot-heartbeat");
        assert_eq!(requests[1].delivery_id, "pilot-heartbeat-1");
        assert_eq!(requests[1].body, br#"{"message":"heartbeat"}"#);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires BONDRY_NTFY_BASE_URL and BONDRY_NTFY_TOPIC"]
    async fn self_hosted_ntfy_accepts_url_template_delivery() -> Result<(), Box<dyn Error>> {
        let base_url = env::var("BONDRY_NTFY_BASE_URL")?;
        let topic = env::var("BONDRY_NTFY_TOPIC")?;
        let secret_ref = SecretRef::new("topic:nightly")?;
        let mut runtime = start_runtime(BTreeMap::from([(
            secret_ref.as_str().to_owned(),
            topic.into_bytes(),
        )]))?;
        runtime.register_route(ntfy_route(
            "self-hosted-ntfy",
            format!("{}/{{secret}}", base_url.trim_end_matches('/')),
            secret_ref,
        )?)?;

        let delivery = DeliveryId::new("nightly-ntfy-delivery")?;
        runtime.emit(
            RouteId::new("self-hosted-ntfy")?,
            delivery.clone(),
            Bytes::from_static(br#"{"message":"Bondry nightly delivery"}"#),
        )?;
        wait_for_delivery(&runtime, &delivery).await?;
        runtime.stop()?;
        Ok(())
    }

    fn start_runtime(values: BTreeMap<String, Vec<u8>>) -> Result<EgressRuntime, Box<dyn Error>> {
        Ok(EgressRuntime::start(
            RouteRegistry::default(),
            EgressRuntimeLimits::default(),
            Arc::new(InMemoryDeliveryLog::default()),
            Arc::new(PilotSecrets { values }),
            Arc::new(NetHttpTransport::new()?),
        )?)
    }

    fn ntfy_route(id: &str, template: String, secret: SecretRef) -> Result<Route, Box<dyn Error>> {
        let payload = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("message")?,
                PayloadFieldType::String,
                true,
            )],
            PayloadLimit::default(),
        )?;
        let template = SecretUrlTemplate::new(template, secret, UrlTemplateLimits::default())?;
        Ok(Route::new(
            RouteId::new(id)?,
            true,
            payload,
            RequestTimeout::new(Duration::from_secs(5))?,
            RetryPolicy::default(),
            RouteAdmissionLimit::default(),
            Arc::new(WebhookDeliveryKind::with_url_template(
                template,
                EndpointPolicy::default(),
                WebhookLimits::default(),
            )),
        ))
    }

    async fn wait_for_delivery(
        runtime: &EgressRuntime,
        delivery: &DeliveryId,
    ) -> Result<(), Box<dyn Error>> {
        for _ in 0..200 {
            if let Some(record) = runtime.delivery(delivery.clone())? {
                match record.state() {
                    DeliveryState::Terminal(DeliveryOutcome::Delivered) => return Ok(()),
                    DeliveryState::Terminal(outcome) => {
                        return Err(
                            std::io::Error::other(format!("delivery failed: {outcome:?}")).into(),
                        );
                    }
                    DeliveryState::Pending => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(std::io::Error::other("delivery did not become terminal").into())
    }

    async fn ntfy_receiver(
        request_count: usize,
    ) -> Result<
        (
            u16,
            JoinHandle<Result<Vec<ReceivedRequest>, std::io::Error>>,
        ),
        std::io::Error,
    > {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let mut requests = Vec::with_capacity(request_count);
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().await?;
                requests.push(read_request(&mut stream).await?);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Ok(requests)
        });
        Ok((port, server))
    }

    async fn read_request(stream: &mut TcpStream) -> Result<ReceivedRequest, std::io::Error> {
        let mut bytes = Vec::new();
        let (header_end, content_length) = loop {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                let content_length = parse_content_length(&bytes[..header_end])?;
                break (header_end + 4, content_length);
            }
        };
        while bytes.len() < header_end + content_length {
            let mut chunk = [0_u8; 4096];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        let header =
            std::str::from_utf8(&bytes[..header_end - 4]).map_err(std::io::Error::other)?;
        let mut lines = header.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| std::io::Error::other("missing request line"))?;
        let mut request_parts = request_line.split_ascii_whitespace();
        if request_parts.next() != Some("POST") {
            return Err(std::io::Error::other("expected POST"));
        }
        let target = request_parts
            .next()
            .ok_or_else(|| std::io::Error::other("missing request target"))?
            .to_owned();
        let delivery_id = lines
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(BONDRY_WEBHOOK_DELIVERY_ID_HEADER)
                    .then(|| value.trim().to_owned())
            })
            .ok_or_else(|| std::io::Error::other("missing delivery ID"))?;
        Ok(ReceivedRequest {
            target,
            delivery_id,
            body: bytes[header_end..header_end + content_length].to_vec(),
        })
    }

    fn parse_content_length(header: &[u8]) -> Result<usize, std::io::Error> {
        let header = std::str::from_utf8(header).map_err(std::io::Error::other)?;
        header
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>())
            })
            .transpose()
            .map_err(std::io::Error::other)?
            .ok_or_else(|| std::io::Error::other("missing content length"))
    }
}
