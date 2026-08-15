#![doc = "End-to-end verification of MCP delivery between Bondry applications."]

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use bondry_core::{
        AdapterId, AuditError, AuditEvent, AuditOutcome, AuditSink, AutomationService,
        CapabilityDescriptor, CapabilityEffect, CapabilityId, CapabilityRegistry, Dispatcher,
        GrantPolicy, InvocationId, InvocationIdGenerationError, InvocationIdGenerator, Principal,
        PrincipalId, PrincipalKind,
    };
    use bondry_delivery_store::{
        DeliveryFailure, DeliveryId, DeliveryOutcome, DeliveryResultCategory, DeliveryState,
        RouteId,
    };
    use bondry_egress::{
        AdmissionError, KindOperationError, PayloadContract, PayloadField, PayloadFieldName,
        PayloadFieldType, PayloadLimit, RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit,
        RouteRegistry,
    };
    use bondry_egress_mcp::{
        McpAuthentication, McpDeliveryKind, McpDiscoveryOperation, McpDiscoveryResult,
        McpDiscoveryTransition, McpLimits, McpToolBinding, McpToolBindingError,
    };
    use bondry_egress_runtime::{
        EgressRuntime, EgressRuntimeError, EgressRuntimeLimits, InMemoryDeliveryLog,
    };
    use bondry_http_server::{
        Authentication, AuthenticationError, BearerAuthenticator, BearerTokenVerifier,
        LocalHttpServer, MountedProtocol, ServerConfiguration,
    };
    use bondry_mcp_proto::{McpAdapter, McpClient, McpClientInfo, McpServerInfo};
    use bondry_secrets::{
        ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue,
        constant_time_eq,
    };
    use bondry_transport::{
        Deadline, EndpointPolicy, HttpRequest, HttpResponse, HttpTransport, NetworkEndpoint,
        TransportError, TransportFuture,
    };
    use bondry_transport_net::NetHttpTransport;
    use bytes::Bytes;
    use http::HeaderValue;
    use serde_json::{Value, json};

    const CAPABILITY: &str = "battery.status";
    const HIDDEN_CAPABILITY: &str = "battery.hidden";
    const PRINCIPAL: &str = "mcp_egress_test_client";
    const SECRET_REFERENCE: &str = "mcp:test-token";
    const TOKEN: &[u8] = b"bondry-mcp-test-token";
    const PRIVATE_ENDPOINT_MARKER: &str = "private-endpoint-marker";
    const PRIVATE_RESULT_MARKER: &str = "private-result-marker";

    #[derive(Default)]
    struct RecordingAudit {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl RecordingAudit {
        fn events(&self) -> Result<Vec<AuditEvent>, AuditError> {
            self.events
                .lock()
                .map(|events| events.clone())
                .map_err(|_| AuditError::Unavailable)
        }
    }

    impl AuditSink for RecordingAudit {
        fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
            self.events
                .lock()
                .map_err(|_| AuditError::Unavailable)?
                .push(event);
            Ok(())
        }
    }

    #[derive(Default)]
    struct SequentialIds(AtomicUsize);

    impl InvocationIdGenerator for SequentialIds {
        fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError> {
            let next = self.0.fetch_add(1, Ordering::Relaxed) + 1;
            InvocationId::new(format!("mcp_egress_{next}")).map_err(|_| InvocationIdGenerationError)
        }
    }

    struct FixedBearerVerifier {
        principal: Principal,
    }

    impl BearerTokenVerifier for FixedBearerVerifier {
        fn verify(&self, token: &str) -> Result<Principal, AuthenticationError> {
            if constant_time_eq(token.as_bytes(), TOKEN) {
                Ok(self.principal.clone())
            } else {
                Err(AuthenticationError::Rejected)
            }
        }
    }

    struct FixedSecrets {
        reference: SecretRef,
    }

    impl SecretProvider for FixedSecrets {
        fn resolve(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
            if reference != &self.reference {
                return Err(SecretProviderError::NotFound);
            }
            SecretValue::new(TOKEN.to_vec())
                .map(ResolvedSecret::current)
                .map_err(|_| SecretProviderError::InvalidMaterial)
        }
    }

    struct Receiver {
        server: LocalHttpServer,
        audit: Arc<RecordingAudit>,
        handler_calls: Arc<AtomicUsize>,
    }

    impl Receiver {
        fn start() -> Result<Self, Box<dyn Error>> {
            let principal =
                Principal::new(PrincipalId::new(PRINCIPAL)?, PrincipalKind::Application);
            let adapter = AdapterId::new("mcp")?;
            let capability = CapabilityId::new(CAPABILITY)?;
            let handler_calls = Arc::new(AtomicUsize::new(0));
            let mut registry = CapabilityRegistry::new();
            let calls = Arc::clone(&handler_calls);
            registry.register(
                CapabilityDescriptor::new(
                    capability.clone(),
                    "Read the current battery status",
                    CapabilityEffect::ReadOnly,
                )?
                .with_input_schema(tool_schema())?,
                move |_context, input: Value| {
                    calls.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if input["large"] == true {
                            return Ok(json!({
                                "marker": PRIVATE_RESULT_MARKER,
                                "value": "x".repeat(8 * 1024),
                            }));
                        }
                        Ok(json!({
                            "charging": true,
                            "detail": input["detail"],
                        }))
                    }
                },
            )?;
            registry.register(
                CapabilityDescriptor::new(
                    CapabilityId::new(HIDDEN_CAPABILITY)?,
                    "A capability without a grant",
                    CapabilityEffect::Mutating,
                )?,
                |_context, _input| async { Ok(json!({ "hidden": true })) },
            )?;

            let policy = Arc::new(GrantPolicy::new());
            policy.grant(principal.id().clone(), adapter.clone(), capability)?;
            let audit = Arc::new(RecordingAudit::default());
            let dispatcher = Dispatcher::from_shared(registry, policy, audit.clone());
            let service: Arc<dyn AutomationService> = Arc::new(dispatcher);
            let mcp = McpAdapter::with_dependencies(
                service,
                adapter,
                Arc::new(SequentialIds::default()),
                McpServerInfo::new("mcp-egress-receiver", "0.2.0")?,
            );
            let verifier: Arc<dyn BearerTokenVerifier> =
                Arc::new(FixedBearerVerifier { principal });
            let configuration = ServerConfiguration::new(Authentication::required(Arc::new(
                BearerAuthenticator::new(verifier),
            )));
            let server = LocalHttpServer::start(configuration, vec![MountedProtocol::Mcp(mcp)])?;
            Ok(Self {
                server,
                audit,
                handler_calls,
            })
        }

        fn endpoint(&self) -> Result<NetworkEndpoint, Box<dyn Error>> {
            Ok(NetworkEndpoint::new(
                format!(
                    "http://127.0.0.1:{}/mcp?opaque={PRIVATE_ENDPOINT_MARKER}",
                    self.server.local_address().port()
                )
                .parse()?,
            )?)
        }
    }

    struct MismatchedVersionTransport {
        inner: NetHttpTransport,
    }

    impl HttpTransport for MismatchedVersionTransport {
        fn send(
            &self,
            request: HttpRequest,
        ) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
            Box::pin(async move {
                let mut parts = request.into_parts();
                parts.headers.insert(
                    "mcp-protocol-version",
                    HeaderValue::from_static("2025-03-26"),
                );
                let request = HttpRequest::new(
                    parts.method,
                    parts.endpoint,
                    parts.headers,
                    parts.body,
                    parts.deadline,
                    parts.policy,
                    parts.limits,
                )?;
                self.inner.send(request).await
            })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn discovers_and_delivers_between_bondry_applications() -> Result<(), Box<dyn Error>> {
        let receiver = Receiver::start()?;
        let secrets = secrets()?;
        let discovery_transport = NetHttpTransport::new()?;
        let endpoint = receiver.endpoint()?;
        let client = client()?;
        let discovery = discover(
            endpoint.clone(),
            client.clone(),
            &secrets,
            &discovery_transport,
        )
        .await?;

        assert_eq!(discovery.tools().len(), 1);
        let tool = &discovery.tools()[0];
        assert_eq!(tool.name(), CAPABILITY);
        assert_eq!(tool.description(), Some("Read the current battery status"));
        assert_eq!(tool.input_schema(), &tool_schema());

        let route = route(
            "bondry-receiver",
            endpoint,
            client,
            discovery.version(),
            tool.binding().clone(),
            McpLimits::default(),
        )?;
        let rendered_route = format!("{route:?}");
        assert!(!rendered_route.contains(PRIVATE_ENDPOINT_MARKER));
        assert!(!rendered_route.contains(SECRET_REFERENCE));
        assert!(!rendered_route.contains(std::str::from_utf8(TOKEN)?));

        let transport: Arc<dyn HttpTransport> = Arc::new(NetHttpTransport::new()?);
        let mut runtime = start_runtime(secrets, transport)?;
        runtime.register_route(route)?;
        let emitted = DeliveryId::new("mcp_emit_success")?;
        runtime.emit(
            RouteId::new("bondry-receiver")?,
            emitted.clone(),
            Bytes::from_static(br#"{"detail":false}"#),
        )?;
        let emitted_record = wait_for_delivery(&runtime, &emitted).await?;
        assert_eq!(
            emitted_record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        assert_eq!(
            emitted_record.result().map(|result| result.category()),
            Some(DeliveryResultCategory::Succeeded)
        );

        let called = DeliveryId::new("mcp_call_success")?;
        let result = runtime.call(
            RouteId::new("bondry-receiver")?,
            called,
            Bytes::from_static(br#"{"detail":true}"#),
        )?;
        let result_json: Value = serde_json::from_slice(result.json())?;
        assert_eq!(result_json["structuredContent"]["charging"], true);
        assert_eq!(result_json["structuredContent"]["detail"], true);
        assert_eq!(
            result.metadata().category(),
            DeliveryResultCategory::Succeeded
        );
        assert_eq!(receiver.handler_calls.load(Ordering::Relaxed), 2);
        assert_success_audit(&receiver.audit.events()?, 2)?;
        runtime.stop()?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_invalid_schema_payload_and_oversized_results() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            McpToolBinding::from_parts(
                CAPABILITY,
                json!({ "type": "not-a-json-schema-type" }),
                McpLimits::default(),
            )
            .err(),
            Some(McpToolBindingError::InvalidSchema)
        );

        let receiver = Receiver::start()?;
        let secrets = secrets()?;
        let discovery_transport = NetHttpTransport::new()?;
        let endpoint = receiver.endpoint()?;
        let client = client()?;
        let discovery = discover(
            endpoint.clone(),
            client.clone(),
            &secrets,
            &discovery_transport,
        )
        .await?;
        let limits = McpLimits::new(16 * 1024, 4 * 1024)?;
        let route = route(
            "bounded-receiver",
            endpoint,
            client,
            discovery.version(),
            discovery.tools()[0].binding().clone(),
            limits,
        )?;
        let transport: Arc<dyn HttpTransport> = Arc::new(NetHttpTransport::new()?);
        let mut runtime = start_runtime(secrets, transport)?;
        runtime.register_route(route)?;

        let invalid = runtime.emit(
            RouteId::new("bounded-receiver")?,
            DeliveryId::new("mcp_invalid_payload")?,
            Bytes::from_static(br#"{"detail":"yes"}"#),
        );
        assert_eq!(
            invalid.err(),
            Some(EgressRuntimeError::Admission(AdmissionError::Kind(
                KindOperationError::InvalidEvent
            )))
        );
        assert_eq!(receiver.handler_calls.load(Ordering::Relaxed), 0);

        let oversized = DeliveryId::new("mcp_oversized_result")?;
        let error = runtime
            .call(
                RouteId::new("bounded-receiver")?,
                oversized.clone(),
                Bytes::from_static(br#"{"detail":true,"large":true}"#),
            )
            .err();
        assert_eq!(
            error,
            Some(EgressRuntimeError::CallFailed(
                DeliveryFailure::ReceiverRejected
            ))
        );
        let record = runtime
            .delivery(oversized)?
            .ok_or("missing oversized result record")?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Failed(DeliveryFailure::ReceiverRejected))
        );
        assert_eq!(
            record.result().map(|result| result.category()),
            Some(DeliveryResultCategory::Invalid)
        );
        let rendered_record = format!("{record:?}");
        assert!(!rendered_record.contains(PRIVATE_RESULT_MARKER));
        assert!(!rendered_record.contains(PRIVATE_ENDPOINT_MARKER));
        assert!(!rendered_record.contains(std::str::from_utf8(TOKEN)?));
        assert_eq!(receiver.handler_calls.load(Ordering::Relaxed), 1);
        assert_success_audit(&receiver.audit.events()?, 1)?;
        runtime.stop()?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fails_closed_when_the_wire_protocol_version_mismatches() -> Result<(), Box<dyn Error>>
    {
        let receiver = Receiver::start()?;
        let secrets = secrets()?;
        let discovery_transport = NetHttpTransport::new()?;
        let endpoint = receiver.endpoint()?;
        let client = client()?;
        let discovery = discover(
            endpoint.clone(),
            client.clone(),
            &secrets,
            &discovery_transport,
        )
        .await?;
        let route = route(
            "version-mismatch",
            endpoint,
            client,
            discovery.version(),
            discovery.tools()[0].binding().clone(),
            McpLimits::default(),
        )?;
        let transport: Arc<dyn HttpTransport> = Arc::new(MismatchedVersionTransport {
            inner: NetHttpTransport::new()?,
        });
        let mut runtime = start_runtime(secrets, transport)?;
        runtime.register_route(route)?;

        let error = runtime
            .call(
                RouteId::new("version-mismatch")?,
                DeliveryId::new("mcp_version_mismatch")?,
                Bytes::from_static(br#"{"detail":true}"#),
            )
            .err();
        assert_eq!(
            error,
            Some(EgressRuntimeError::CallFailed(
                DeliveryFailure::ReceiverRejected
            ))
        );
        assert_eq!(receiver.handler_calls.load(Ordering::Relaxed), 0);
        assert!(receiver.audit.events()?.is_empty());
        runtime.stop()?;
        Ok(())
    }

    fn secrets() -> Result<Arc<FixedSecrets>, Box<dyn Error>> {
        Ok(Arc::new(FixedSecrets {
            reference: SecretRef::new(SECRET_REFERENCE)?,
        }))
    }

    fn client() -> Result<McpClient, Box<dyn Error>> {
        Ok(McpClient::new(McpClientInfo::new(
            "bondry-egress-e2e",
            "0.2.0",
        )?))
    }

    async fn discover(
        endpoint: NetworkEndpoint,
        client: McpClient,
        secrets: &FixedSecrets,
        transport: &dyn HttpTransport,
    ) -> Result<McpDiscoveryResult, Box<dyn Error>> {
        let mut operation = McpDiscoveryOperation::new(
            endpoint,
            McpAuthentication::Bearer(secrets.reference.clone()),
            EndpointPolicy::default(),
            client,
            Default::default(),
        )?;
        let rendered = format!("{operation:?}");
        assert!(!rendered.contains(PRIVATE_ENDPOINT_MARKER));
        assert!(!rendered.contains(SECRET_REFERENCE));
        assert!(!rendered.contains(std::str::from_utf8(TOKEN)?));
        let resolved = operation
            .secret_references()
            .iter()
            .map(|reference| secrets.resolve(reference))
            .collect::<Result<Vec<_>, _>>()?;
        let deadline = Deadline::at(Instant::now() + Duration::from_secs(5));
        let mut transition = operation.start(deadline, resolved);
        loop {
            match transition {
                McpDiscoveryTransition::Http(request) => {
                    transition = operation.resume(transport.send(*request).await);
                }
                McpDiscoveryTransition::Complete(result) => return Ok(result?),
            }
        }
    }

    fn route(
        id: &str,
        endpoint: NetworkEndpoint,
        client: McpClient,
        version: bondry_mcp_proto::McpProtocolVersion,
        binding: McpToolBinding,
        limits: McpLimits,
    ) -> Result<Route, Box<dyn Error>> {
        let kind = McpDeliveryKind::new(
            endpoint,
            McpAuthentication::Bearer(SecretRef::new(SECRET_REFERENCE)?),
            EndpointPolicy::default(),
            client,
            version,
            binding,
            limits,
        )?;
        let payload = PayloadContract::new(
            [
                PayloadField::new(
                    PayloadFieldName::new("detail")?,
                    PayloadFieldType::Any,
                    true,
                ),
                PayloadField::new(
                    PayloadFieldName::new("large")?,
                    PayloadFieldType::Any,
                    false,
                ),
            ],
            PayloadLimit::default(),
        )?;
        Ok(Route::new(
            RouteId::new(id)?,
            true,
            payload,
            RequestTimeout::new(Duration::from_secs(5))?,
            RetryPolicy::without_retries(),
            RouteAdmissionLimit::default(),
            Arc::new(kind),
        ))
    }

    fn tool_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "detail": { "type": "boolean" },
                "large": { "type": "boolean" },
            },
            "required": ["detail"],
            "additionalProperties": false,
        })
    }

    fn start_runtime(
        secrets: Arc<FixedSecrets>,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<EgressRuntime, Box<dyn Error>> {
        Ok(EgressRuntime::start(
            RouteRegistry::default(),
            EgressRuntimeLimits::default(),
            Arc::new(InMemoryDeliveryLog::default()),
            secrets,
            transport,
        )?)
    }

    async fn wait_for_delivery(
        runtime: &EgressRuntime,
        delivery: &DeliveryId,
    ) -> Result<bondry_delivery_store::DeliveryRecord, Box<dyn Error>> {
        for _ in 0..200 {
            if let Some(record) = runtime.delivery(delivery.clone())? {
                if record.state().is_terminal() {
                    return Ok(record);
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(std::io::Error::other("delivery did not become terminal").into())
    }

    fn assert_success_audit(
        events: &[AuditEvent],
        invocations: usize,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(events.len(), invocations * 2);
        for (index, event) in events.iter().enumerate() {
            assert_eq!(event.principal().as_str(), PRINCIPAL);
            assert_eq!(event.adapter().as_str(), "mcp");
            assert_eq!(event.capability().as_str(), CAPABILITY);
            let expected = if index % 2 == 0 {
                AuditOutcome::Started
            } else {
                AuditOutcome::Succeeded
            };
            assert_eq!(event.outcome(), &expected);
        }
        Ok(())
    }
}
