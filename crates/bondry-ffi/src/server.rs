use std::{net::IpAddr, ptr, slice, sync::Arc, time::Duration};

use bondry_auth::{AuthManager, AuthStore};
use bondry_core::{AutomationService, Principal, PrincipalId, PrincipalKind};
use bondry_http::{
    Authentication, HttpAdapter, LocalHttpServer, OriginPolicy, RateLimits, ServerConfiguration,
    ServerStartError,
};
use bondry_mcp::{McpAdapter, McpServerInfo};
use bondry_rest::RestAdapter;
use serde::Deserialize;

use crate::{
    BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON,
    BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK,
    BONDRY_STATUS_PAYLOAD_TOO_LARGE, BONDRY_STATUS_SERVER_BIND, BONDRY_STATUS_SERVER_START,
    BONDRY_STATUS_SERVER_STOP, BondryStoreHandle, StoreHandle,
    capabilities::ForeignAutomationService, catch_status, records::terminated,
};

/// The first JSON server-configuration contract version.
pub const BONDRY_SERVER_CONFIGURATION_VERSION_V1: u32 = 1;
/// Capacity of the terminated textual IP address in a server-address record.
pub const BONDRY_SERVER_ADDRESS_CAPACITY_V1: usize = 46;
const MAX_CONFIGURATION_LENGTH: usize = 65_536;

/// An opaque running-server handle owned by the caller.
#[repr(C)]
pub struct BondryServerHandle {
    _private: [u8; 0],
}

struct ServerHandle {
    server: LocalHttpServer,
}

/// The bound local address returned after server startup.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryServerAddressV1 {
    /// UTF-8 IP address, terminated with zero.
    pub address: [u8; BONDRY_SERVER_ADDRESS_CAPACITY_V1],
    /// Bound TCP port.
    pub port: u16,
}

impl BondryServerAddressV1 {
    fn from_server(server: &LocalHttpServer) -> Self {
        let address = server.local_address();
        Self {
            address: terminated(&address.ip().to_string()),
            port: address.port(),
        }
    }

    const fn zeroed() -> Self {
        Self {
            address: [0; BONDRY_SERVER_ADDRESS_CAPACITY_V1],
            port: 0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputConfiguration {
    version: u32,
    bind_address: String,
    port: u16,
    authentication: InputAuthentication,
    adapters: Vec<InputAdapter>,
    mcp_server: Option<InputMcpServer>,
    allowed_origins: Vec<String>,
    requests_per_minute: u32,
    authentication_failures_per_minute: u32,
    max_body_bytes: usize,
    max_connections: usize,
    header_read_timeout_milliseconds: u64,
    request_timeout_milliseconds: u64,
    shutdown_grace_period_milliseconds: u64,
    allow_cleartext_network: bool,
    allow_unauthenticated_network: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputAuthentication {
    mode: InputAuthenticationMode,
    principal_id: Option<String>,
    principal_kind: Option<InputPrincipalKind>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InputAuthenticationMode {
    Bearer,
    Disabled,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputPrincipalKind {
    User,
    Application,
    System,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InputAdapter {
    Rest,
    Mcp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputMcpServer {
    name: String,
    title: Option<String>,
    version: String,
}

/// Starts enabled REST and MCP adapters from a validated JSON configuration.
///
/// # Safety
///
/// `store` must be a live store handle. The configuration must be readable for its declared
/// length. Both output pointers must be writable. The returned server handle must be stopped once.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_start_v1(
    store: *const BondryStoreHandle,
    configuration_json: *const u8,
    configuration_json_length: usize,
    out_server: *mut *mut BondryServerHandle,
    out_address: *mut BondryServerAddressV1,
) -> i32 {
    if out_server.is_null() || out_address.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: Both output pointers were validated as non-null and are writable by contract.
    unsafe {
        out_server.write(ptr::null_mut());
        out_address.write(BondryServerAddressV1::zeroed());
    }
    catch_status(|| {
        if store.is_null() || configuration_json.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        if configuration_json_length > isize::MAX as usize {
            return BONDRY_STATUS_INVALID_LENGTH;
        }
        if configuration_json_length > MAX_CONFIGURATION_LENGTH {
            return BONDRY_STATUS_PAYLOAD_TOO_LARGE;
        }
        // SAFETY: The configuration buffer is non-null, bounded, and readable by contract.
        let bytes = unsafe { slice::from_raw_parts(configuration_json, configuration_json_length) };
        let value: serde_json::Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return BONDRY_STATUS_INVALID_JSON,
        };
        let input: InputConfiguration = match serde_json::from_value(value) {
            Ok(input) => input,
            Err(_) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        // SAFETY: The caller guarantees that store is a live Bondry handle.
        let store = unsafe { &*store.cast::<StoreHandle>() };
        let server = match start_server(store, input) {
            Ok(server) => server,
            Err(status) => return status,
        };
        let address = BondryServerAddressV1::from_server(&server);
        let handle = Box::new(ServerHandle { server });
        // SAFETY: Outputs are writable and receive the address plus one server ownership unit.
        unsafe {
            out_address.write(address);
            out_server.write(Box::into_raw(handle).cast::<BondryServerHandle>());
        }
        BONDRY_STATUS_OK
    })
}

/// Stops a running local server and consumes its handle. Passing null is a no-op.
///
/// # Safety
///
/// A non-null value must be a live handle returned by `bondry_server_start_v1` and must not be used
/// or stopped again after this function begins.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_stop_v1(server: *mut BondryServerHandle) -> i32 {
    if server.is_null() {
        return BONDRY_STATUS_OK;
    }
    catch_status(|| {
        // SAFETY: The caller transfers exactly one live server ownership unit.
        let mut handle = unsafe { Box::from_raw(server.cast::<ServerHandle>()) };
        match handle.server.stop() {
            Ok(()) => BONDRY_STATUS_OK,
            Err(_) => BONDRY_STATUS_SERVER_STOP,
        }
    })
}

fn start_server(store: &StoreHandle, input: InputConfiguration) -> Result<LocalHttpServer, i32> {
    if input.version != BONDRY_SERVER_CONFIGURATION_VERSION_V1 || input.adapters.is_empty() {
        return Err(BONDRY_STATUS_INVALID_ARGUMENT);
    }
    let bind_address = input
        .bind_address
        .parse::<IpAddr>()
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    let authentication = authentication(store, &input.authentication)?;
    let limits = RateLimits::new(
        input.requests_per_minute,
        input.authentication_failures_per_minute,
    )
    .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    let mut origins = OriginPolicy::deny_browser_origins();
    for origin in &input.allowed_origins {
        origins = origins
            .allowing(origin)
            .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    }
    let mut configuration = ServerConfiguration::new(authentication)
        .with_bind_address(bind_address)
        .with_port(input.port)
        .with_origin_policy(origins)
        .with_rate_limits(limits)
        .with_max_body_bytes(input.max_body_bytes)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?
        .with_max_connections(input.max_connections)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?
        .with_timeouts(
            Duration::from_millis(input.header_read_timeout_milliseconds),
            Duration::from_millis(input.request_timeout_milliseconds),
            Duration::from_millis(input.shutdown_grace_period_milliseconds),
        )
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    if input.allow_cleartext_network {
        configuration = configuration.allowing_cleartext_network();
    }
    if input.allow_unauthenticated_network {
        configuration = configuration.allowing_unauthenticated_network();
    }

    let service: Arc<dyn AutomationService> = Arc::new(ForeignAutomationService::new(
        store.store.clone(),
        store.capabilities.clone(),
    ));
    let mut adapters: Vec<Arc<dyn HttpAdapter>> = Vec::with_capacity(input.adapters.len());
    let mut has_rest = false;
    let mut has_mcp = false;
    for adapter in input.adapters {
        match adapter {
            InputAdapter::Rest if !has_rest => {
                has_rest = true;
                adapters.push(Arc::new(
                    RestAdapter::new(service.clone())
                        .map_err(|_| BONDRY_STATUS_INTERNAL_FAILURE)?,
                ));
            }
            InputAdapter::Mcp if !has_mcp => {
                has_mcp = true;
                let info = mcp_server_info(input.mcp_server.as_ref())?;
                adapters.push(Arc::new(
                    McpAdapter::new(service.clone(), info)
                        .map_err(|_| BONDRY_STATUS_INTERNAL_FAILURE)?,
                ));
            }
            _ => return Err(BONDRY_STATUS_INVALID_ARGUMENT),
        }
    }
    if !has_mcp && input.mcp_server.is_some() {
        return Err(BONDRY_STATUS_INVALID_ARGUMENT);
    }
    LocalHttpServer::start(configuration, adapters).map_err(server_start_status)
}

fn authentication(store: &StoreHandle, input: &InputAuthentication) -> Result<Authentication, i32> {
    match input.mode {
        InputAuthenticationMode::Bearer
            if input.principal_id.is_none() && input.principal_kind.is_none() =>
        {
            let auth_store: Arc<dyn AuthStore> = store.store.clone();
            Ok(Authentication::bearer(Arc::new(AuthManager::from_shared(
                auth_store,
            ))))
        }
        InputAuthenticationMode::Disabled => {
            let id = input
                .principal_id
                .as_deref()
                .ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
            let kind = input.principal_kind.ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
            let id = PrincipalId::new(id).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
            Ok(Authentication::disabled(Principal::new(
                id,
                match kind {
                    InputPrincipalKind::User => PrincipalKind::User,
                    InputPrincipalKind::Application => PrincipalKind::Application,
                    InputPrincipalKind::System => PrincipalKind::System,
                },
            )))
        }
        InputAuthenticationMode::Bearer => Err(BONDRY_STATUS_INVALID_ARGUMENT),
    }
}

fn mcp_server_info(input: Option<&InputMcpServer>) -> Result<McpServerInfo, i32> {
    let input = input.ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
    let mut info = McpServerInfo::new(&input.name, &input.version)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    if let Some(title) = &input.title {
        info = info
            .with_title(title)
            .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    }
    Ok(info)
}

fn server_start_status(error: ServerStartError) -> i32 {
    match error {
        ServerStartError::Configuration(_) | ServerStartError::NoAdapters => {
            BONDRY_STATUS_INVALID_ARGUMENT
        }
        ServerStartError::Bind(_) => BONDRY_STATUS_SERVER_BIND,
        ServerStartError::Runtime(_) | ServerStartError::Thread(_) | ServerStartError::Startup => {
            BONDRY_STATUS_SERVER_START
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        ffi::c_void,
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        ptr,
        sync::{Arc, RwLock},
        time::Duration,
    };

    use bondry_auth::{AuthManager, AuthStore, ClientName};
    use bondry_store_sqlcipher::{DatabaseKey, SqlCipherStore};
    use serde_json::{Value, json};
    use tempfile::tempdir;

    use super::{BondryServerAddressV1, BondryServerHandle};
    use crate::{
        BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON, BONDRY_STATUS_NULL_POINTER,
        BONDRY_STATUS_OK, BONDRY_STATUS_PAYLOAD_TOO_LARGE, BONDRY_STATUS_SERVER_BIND,
        BondryCapabilityCompletionV1, BondryInvocationV1, BondryStoreHandle, StoreHandle,
        bondry_capability_register_v1, bondry_capability_unregister_v1, bondry_grant_add_v1,
        bondry_server_start_v1, bondry_server_stop_v1, capabilities::RegisteredCapability,
        records::BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
    };

    #[test]
    fn validates_json_configuration_and_initializes_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, store) = test_store()?;
        let store_pointer = ptr::from_ref(&store).cast::<BondryStoreHandle>();
        let mut server = ptr::dangling_mut::<BondryServerHandle>();
        let mut address = BondryServerAddressV1 {
            address: [1; 46],
            port: 1,
        };

        assert_eq!(
            unsafe {
                bondry_server_start_v1(
                    store_pointer,
                    b"{}".as_ptr(),
                    2,
                    ptr::null_mut(),
                    &mut address,
                )
            },
            BONDRY_STATUS_NULL_POINTER
        );
        assert_eq!(
            unsafe {
                bondry_server_start_v1(
                    store_pointer,
                    b"not-json".as_ptr(),
                    8,
                    &mut server,
                    &mut address,
                )
            },
            BONDRY_STATUS_INVALID_JSON
        );
        assert!(server.is_null());
        assert_eq!(address.port, 0);
        assert!(address.address.iter().all(|byte| *byte == 0));

        for invalid in [
            configuration(json!([]), Value::Null, bearer_authentication()),
            configuration(
                json!(["rest", "rest"]),
                Value::Null,
                bearer_authentication(),
            ),
            configuration(json!(["mcp"]), Value::Null, bearer_authentication()),
            configuration(
                json!(["rest"]),
                json!({ "name": "app", "version": "1" }),
                bearer_authentication(),
            ),
            configuration(
                json!(["rest"]),
                Value::Null,
                json!({ "mode": "disabled", "principalId": null, "principalKind": null }),
            ),
        ] {
            assert_eq!(
                start(store_pointer, &invalid, &mut server, &mut address),
                BONDRY_STATUS_INVALID_ARGUMENT
            );
            assert!(server.is_null());
        }

        let oversized = vec![b' '; 65_537];
        assert_eq!(
            start(store_pointer, &oversized, &mut server, &mut address),
            BONDRY_STATUS_PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            unsafe { bondry_server_stop_v1(ptr::null_mut()) },
            BONDRY_STATUS_OK
        );
        Ok(())
    }

    #[test]
    fn starts_routes_and_stops_both_adapters() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, store) = test_store()?;
        let store_pointer = ptr::from_ref(&store).cast::<BondryStoreHandle>();
        let input = configuration(
            json!(["rest", "mcp"]),
            json!({ "name": "test-app", "title": "Test App", "version": "1.0" }),
            disabled_authentication(),
        );
        let mut server = ptr::null_mut();
        let mut address = BondryServerAddressV1::zeroed();
        assert_eq!(
            start(store_pointer, &input, &mut server, &mut address),
            BONDRY_STATUS_OK
        );
        assert!(!server.is_null());
        assert_eq!(utf8_address(&address)?, "127.0.0.1");
        assert_ne!(address.port, 0);

        let response = request(
            address.port,
            "GET /api/v1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"v1\""));
        let response = request(address.port, "GET /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn reports_port_conflicts() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, store) = test_store()?;
        let store_pointer = ptr::from_ref(&store).cast::<BondryStoreHandle>();
        let mut first = ptr::null_mut();
        let mut first_address = BondryServerAddressV1::zeroed();
        let input = configuration(json!(["rest"]), Value::Null, disabled_authentication());
        assert_eq!(
            start(store_pointer, &input, &mut first, &mut first_address),
            BONDRY_STATUS_OK
        );

        let mut conflicting: Value = serde_json::from_slice(&input)?;
        conflicting["port"] = json!(first_address.port);
        let conflicting = serde_json::to_vec(&conflicting)?;
        let mut second = ptr::null_mut();
        let mut second_address = BondryServerAddressV1::zeroed();
        assert_eq!(
            start(
                store_pointer,
                &conflicting,
                &mut second,
                &mut second_address,
            ),
            BONDRY_STATUS_SERVER_BIND
        );
        assert!(second.is_null());
        assert_eq!(unsafe { bondry_server_stop_v1(first) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn authenticates_with_tokens_from_the_shared_store() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, store) = test_store()?;
        let client = store.auth.create_client(ClientName::new("HTTP Client")?)?;
        let token = store.auth.issue_token(client.id(), None, None)?;
        let authorization = format!("Authorization: Bearer {}", token.secret().expose());
        let store_pointer = ptr::from_ref(&store).cast::<BondryStoreHandle>();
        let input = configuration(json!(["rest"]), Value::Null, bearer_authentication());
        let mut server = ptr::null_mut();
        let mut address = BondryServerAddressV1::zeroed();
        assert_eq!(
            start(store_pointer, &input, &mut server, &mut address),
            BONDRY_STATUS_OK
        );

        let rejected = request(
            address.port,
            "GET /api/v1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
        let accepted = request(
            address.port,
            &format!("GET /api/v1 HTTP/1.1\r\nHost: localhost\r\n{authorization}\r\n\r\n"),
        )?;
        assert!(accepted.starts_with("HTTP/1.1 200 OK"));
        assert!(!accepted.contains(token.secret().expose()));
        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn observes_live_capability_registration() -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, store) = test_store()?;
        let store_pointer = ptr::from_ref(&store).cast::<BondryStoreHandle>();
        let handler_context = Box::into_raw(Box::new(())).cast::<c_void>();
        assert_eq!(
            unsafe {
                bondry_capability_register_v1(
                    store_pointer,
                    b"battery.read".as_ptr(),
                    12,
                    b"Read battery state".as_ptr(),
                    18,
                    BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                    handler_context,
                    Some(test_handler),
                    Some(release_handler),
                )
            },
            BONDRY_STATUS_OK
        );
        let mut changed = 0;
        assert_eq!(
            unsafe {
                bondry_grant_add_v1(
                    store_pointer,
                    b"local-test".as_ptr(),
                    10,
                    b"rest".as_ptr(),
                    4,
                    b"battery.read".as_ptr(),
                    12,
                    &mut changed,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(changed, 1);

        let input = configuration(json!(["rest"]), Value::Null, disabled_authentication());
        let mut server = ptr::null_mut();
        let mut address = BondryServerAddressV1::zeroed();
        assert_eq!(
            start(store_pointer, &input, &mut server, &mut address),
            BONDRY_STATUS_OK
        );
        let listed = request(
            address.port,
            "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(listed.contains("battery.read"));

        assert_eq!(
            unsafe {
                bondry_capability_unregister_v1(
                    store_pointer,
                    b"battery.read".as_ptr(),
                    12,
                    &mut changed,
                )
            },
            BONDRY_STATUS_OK
        );
        let listed = request(
            address.port,
            "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(!listed.contains("battery.read"));
        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        Ok(())
    }

    unsafe extern "C" fn test_handler(
        _context: *mut c_void,
        _invocation: *const BondryInvocationV1,
        completion: BondryCapabilityCompletionV1,
        completion_context: *mut c_void,
    ) {
        // SAFETY: The test consumes the provided completion context exactly once.
        unsafe {
            completion(
                completion_context,
                1,
                br#"{"ok":true}"#.as_ptr(),
                br#"{"ok":true}"#.len(),
            );
        }
    }

    unsafe extern "C" fn release_handler(context: *mut c_void) {
        if !context.is_null() {
            // SAFETY: Registration transferred one Box allocation to this callback.
            unsafe { drop(Box::from_raw(context.cast::<()>())) };
        }
    }

    fn test_store() -> Result<(tempfile::TempDir, StoreHandle), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let key = DatabaseKey::from_slice(&[0x73; 32])?;
        let store = Arc::new(SqlCipherStore::open(
            directory.path().join("bondry.db"),
            &key,
        )?);
        let auth_store: Arc<dyn AuthStore> = store.clone();
        Ok((
            directory,
            StoreHandle {
                store,
                auth: AuthManager::from_shared(auth_store),
                capabilities: Arc::new(RwLock::new(HashMap::<_, RegisteredCapability>::new())),
            },
        ))
    }

    fn configuration(adapters: Value, mcp_server: Value, authentication: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "bindAddress": "127.0.0.1",
            "port": 0,
            "authentication": authentication,
            "adapters": adapters,
            "mcpServer": mcp_server,
            "allowedOrigins": [],
            "requestsPerMinute": 120,
            "authenticationFailuresPerMinute": 30,
            "maxBodyBytes": 1_048_576,
            "maxConnections": 64,
            "headerReadTimeoutMilliseconds": 5_000,
            "requestTimeoutMilliseconds": 30_000,
            "shutdownGracePeriodMilliseconds": 2_000,
            "allowCleartextNetwork": false,
            "allowUnauthenticatedNetwork": false,
        }))
        .unwrap_or_default()
    }

    fn bearer_authentication() -> Value {
        json!({ "mode": "bearer", "principalId": null, "principalKind": null })
    }

    fn disabled_authentication() -> Value {
        json!({
            "mode": "disabled",
            "principalId": "local-test",
            "principalKind": "application",
        })
    }

    fn start(
        store: *const BondryStoreHandle,
        input: &[u8],
        server: &mut *mut BondryServerHandle,
        address: &mut BondryServerAddressV1,
    ) -> i32 {
        // SAFETY: Test inputs and outputs remain live for the complete call.
        unsafe { bondry_server_start_v1(store, input.as_ptr(), input.len(), server, address) }
    }

    fn request(port: u16, request: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            Duration::from_secs(1),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    fn utf8_address(address: &BondryServerAddressV1) -> Result<&str, Box<dyn std::error::Error>> {
        let length = address
            .address
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(address.address.len());
        Ok(std::str::from_utf8(&address.address[..length])?)
    }
}
