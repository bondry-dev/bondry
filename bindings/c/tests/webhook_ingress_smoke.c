#include "bondry.h"
#include "bondry_local_server.h"
#include "bondry_webhook_ingress.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct HandlerState {
    int invocations;
    int releases;
} HandlerState;

typedef struct SecretState {
    int references;
} SecretState;

static void invoke_capability(
    void *handler_context,
    const BondryInvocationV1 *invocation,
    BondryCapabilityCompletionV1 completion,
    void *completion_context
) {
    HandlerState *state = (HandlerState *)handler_context;
    state->invocations += 1;
    const uint8_t output[] = "{}";
    completion(
        completion_context,
        BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
        output,
        sizeof(output) - 1
    );
    (void)invocation;
}

static void release_capability(void *handler_context) {
    HandlerState *state = (HandlerState *)handler_context;
    state->releases += 1;
}

static void *retain_secrets(void *context) {
    SecretState *state = (SecretState *)context;
    state->references += 1;
    return context;
}

static void release_secrets(void *context) {
    SecretState *state = (SecretState *)context;
    state->references -= 1;
}

static BondryStatus resolve_secret(
    void *provider_context,
    const uint8_t *secret_reference,
    size_t secret_reference_length,
    BondryWebhookSecretResolutionV1 completion,
    void *completion_context
) {
    const uint8_t reference[] = "keychain:smoke";
    const uint8_t secret[] = "smoke-secret";
    if (provider_context == NULL || completion == NULL ||
        secret_reference_length != sizeof(reference) - 1 ||
        memcmp(secret_reference, reference, sizeof(reference) - 1) != 0) {
        return BONDRY_STATUS_NOT_FOUND;
    }
    completion(completion_context, secret, sizeof(secret) - 1, NULL, 0, 0);
    return BONDRY_STATUS_OK;
}

static int response_status(const BondryServerAddressV1 *address) {
    int socket_handle = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_handle < 0) {
        return 0;
    }
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(address->port);
    if (inet_pton(AF_INET, (const char *)address->address, &peer.sin_addr) != 1 ||
        connect(socket_handle, (const struct sockaddr *)&peer, sizeof(peer)) != 0) {
        close(socket_handle);
        return 0;
    }
    const char request[] =
        "POST /hooks/smoke HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Authorization: Bearer smoke-secret\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 14\r\n"
        "Connection: close\r\n\r\n"
        "{\"value\":true}";
    if (send(socket_handle, request, sizeof(request) - 1, 0) != sizeof(request) - 1) {
        close(socket_handle);
        return 0;
    }
    char response[256];
    ssize_t received = recv(socket_handle, response, sizeof(response) - 1, 0);
    close(socket_handle);
    if (received <= 0) {
        return 0;
    }
    response[received] = 0;
    return strncmp(response, "HTTP/1.1 204", strlen("HTTP/1.1 204")) == 0;
}

int main(int argc, char **argv) {
    if (argc != 2 ||
        bondry_webhook_ingress_abi_version_v1() != BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1) {
        return 1;
    }
    uint8_t key[32];
    memset(key, 0xA6, sizeof(key));
    BondryStoreHandle *store = NULL;
    BondryStatus status = bondry_store_open_v1(
        (const uint8_t *)argv[1],
        strlen(argv[1]),
        key,
        sizeof(key),
        &store
    );
    if (status != BONDRY_STATUS_OK || store == NULL) {
        return 2;
    }

    HandlerState handler_state = {0, 0};
    if (bondry_capability_register_v1(
            store,
            (const uint8_t *)"smoke.receive",
            strlen("smoke.receive"),
            (const uint8_t *)"Receive smoke webhook",
            strlen("Receive smoke webhook"),
            BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
            &handler_state,
            invoke_capability,
            release_capability
        ) != BONDRY_STATUS_OK) {
        return 3;
    }
    uint8_t changed = 0;
    if (bondry_grant_add_v1(
            store,
            (const uint8_t *)"smoke-client",
            strlen("smoke-client"),
            (const uint8_t *)"webhook",
            strlen("webhook"),
            (const uint8_t *)"smoke.receive",
            strlen("smoke.receive"),
            &changed
        ) != BONDRY_STATUS_OK || changed != 1) {
        return 4;
    }

    const char server_configuration[] =
        "{\"version\":1,\"bindAddress\":\"127.0.0.1\",\"port\":0,"
        "\"authentication\":{\"mode\":\"bearer\",\"principalId\":null,"
        "\"principalKind\":null},\"adapters\":[],\"mcpServer\":null,"
        "\"allowedOrigins\":[],\"requestsPerMinute\":120,"
        "\"authenticationFailuresPerMinute\":30,\"maxBodyBytes\":1048576,"
        "\"maxConnections\":64,\"headerReadTimeoutMilliseconds\":5000,"
        "\"requestTimeoutMilliseconds\":30000,"
        "\"shutdownGracePeriodMilliseconds\":2000,"
        "\"rawBodyLimits\":{\"aggregateRetainedBytes\":8388608,"
        "\"shutdownDrainDeadlineMilliseconds\":10000},"
        "\"allowCleartextNetwork\":false,\"allowUnauthenticatedNetwork\":false}";
    BondryServerHandle *server = NULL;
    BondryServerAddressV1 address;
    status = bondry_server_start_v1(
        store,
        (const uint8_t *)server_configuration,
        sizeof(server_configuration) - 1,
        &server,
        &address
    );
    if (status != BONDRY_STATUS_OK || server == NULL) {
        return 5;
    }

    BondryAutomationServiceV1 automation;
    BondryDedupStoreV1 dedup;
    if (bondry_automation_service_v1(store, &automation) != BONDRY_STATUS_OK ||
        bondry_store_dedup_v1(store, 100000, 16777216, 604800, &dedup) != BONDRY_STATUS_OK) {
        return 6;
    }
    size_t capabilities_length = 0;
    status = automation.capabilities(
        automation.context,
        (const uint8_t *)"smoke-client",
        strlen("smoke-client"),
        BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
        (const uint8_t *)"webhook",
        strlen("webhook"),
        NULL,
        0,
        &capabilities_length
    );
    if (status != BONDRY_STATUS_OK || capabilities_length == 0) {
        fprintf(
            stderr,
            "capability discovery failed: status=%d length=%zu\n",
            status,
            capabilities_length
        );
        return 6;
    }
    SecretState secret_state = {0};
    BondryWebhookSecretProviderV1 secrets = {
        BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1,
        sizeof(BondryWebhookSecretProviderV1),
        &secret_state,
        retain_secrets,
        release_secrets,
        resolve_secret,
    };
    const char route_configuration[] =
        "{\"version\":1,\"routeId\":\"smoke\",\"path\":\"/hooks/smoke\","
        "\"principal\":{\"id\":\"smoke-client\",\"kind\":\"application\"},"
        "\"capabilityId\":\"smoke.receive\",\"semantics\":\"read_only\","
        "\"verifier\":{\"type\":\"bearer\","
        "\"secretRef\":\"keychain:smoke\"},\"mapping\":{\"type\":\"json_body\"},"
        "\"successStatus\":204}";
    BondryWebhookIngressRegistrationDescriptorV1 descriptor = {
        BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1,
        sizeof(BondryWebhookIngressRegistrationDescriptorV1),
        (const uint8_t *)route_configuration,
        sizeof(route_configuration) - 1,
        automation,
        dedup,
        secrets,
    };
    BondryRawBodyHandlerDescriptorV1 raw_handler;
    status = bondry_webhook_ingress_handler_v1(&descriptor, &raw_handler);
    automation.release(automation.context);
    dedup.release(dedup.context);
    if (status != BONDRY_STATUS_OK || secret_state.references != 1) {
        fprintf(
            stderr,
            "ingress handler creation failed: status=%d secret_references=%d\n",
            status,
            secret_state.references
        );
        return 7;
    }

    BondryRawBodyRegistrationHandle *registration = NULL;
    status = bondry_server_raw_body_handler_register_v1(server, &raw_handler, &registration);
    bondry_webhook_ingress_handler_release_v1(&raw_handler);
    if (status != BONDRY_STATUS_OK || registration == NULL || !response_status(&address) ||
        handler_state.invocations != 1) {
        return 8;
    }
    if (bondry_server_raw_body_handler_disable_v1(registration, 5000) != BONDRY_STATUS_OK) {
        return 9;
    }
    bondry_server_raw_body_handler_release_v1(registration);
    if (secret_state.references != 0 || bondry_server_stop_v1(server) != BONDRY_STATUS_OK ||
        bondry_store_close_v1(store) != BONDRY_STATUS_OK || handler_state.releases != 1) {
        return 10;
    }
    return 0;
}
