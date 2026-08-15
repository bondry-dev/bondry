#include "bondry.h"
#include "bondry_egress.h"

#include <string.h>
#include <time.h>

static void *retain_context(void *context) {
    return context;
}

static void release_context(void *context) {
    (void)context;
}

static BondryStatus send_http(
    void *transport_context,
    const BondryHTTPRequestV1 *request,
    BondryHTTPCompletionV1 completion,
    void *completion_context
) {
    if (transport_context == NULL || request == NULL || completion == NULL ||
        request->method_length != 4 ||
        memcmp(request->method, "POST", request->method_length) != 0) {
        return BONDRY_STATUS_INVALID_ARGUMENT;
    }
    static const uint8_t server_name[] = "example.com";
    BondryHTTPResultV1 result = {0};
    result.kind = BONDRY_HTTP_RESULT_RESPONSE_V1;
    result.status_code = 204;
    result.connection.kind = BONDRY_CONNECTION_EVIDENCE_TLS_V1;
    result.connection.server_name = server_name;
    result.connection.server_name_length = sizeof(server_name) - 1;
    completion(completion_context, &result);
    return BONDRY_STATUS_OK;
}

static BondryStatus resolve_secret(
    void *provider_context,
    const uint8_t *secret_reference,
    size_t secret_reference_length,
    BondrySecretResolutionV1 completion,
    void *completion_context
) {
    (void)provider_context;
    (void)secret_reference;
    (void)secret_reference_length;
    (void)completion;
    (void)completion_context;
    return BONDRY_STATUS_NOT_FOUND;
}

int main(int argc, char **argv) {
    if (argc != 2 || bondry_egress_abi_version_v1() != BONDRY_EGRESS_ABI_VERSION_V1) {
        return 1;
    }
    uint8_t key[32];
    memset(key, 0x5A, sizeof(key));
    BondryStoreHandle *store = NULL;
    if (bondry_store_open_v1(
            (const uint8_t *)argv[1],
            strlen(argv[1]),
            key,
            sizeof(key),
            &store
        ) != BONDRY_STATUS_OK) {
        return 2;
    }

    uint8_t context = 1;
    BondryHTTPTransportV1 transport = {
        .abi_version = BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1,
        .struct_size = sizeof(BondryHTTPTransportV1),
        .context = &context,
        .retain = retain_context,
        .release = release_context,
        .send = send_http,
    };
    BondrySecretProviderV1 secrets = {
        .abi_version = BONDRY_SECRET_PROVIDER_ABI_VERSION_V1,
        .struct_size = sizeof(BondrySecretProviderV1),
        .context = &context,
        .retain = retain_context,
        .release = release_context,
        .resolve = resolve_secret,
    };
    static const uint8_t runtime[] = "{\"version\":1}";
    BondryEgressHandle *egress = NULL;
    if (bondry_egress_start_v1(
            store,
            runtime,
            sizeof(runtime) - 1,
            &transport,
            &secrets,
            &egress
        ) != BONDRY_STATUS_OK || egress == NULL) {
        return 3;
    }

    static const uint8_t route[] =
        "{\"version\":1,\"id\":\"receiver\",\"payload\":{\"fields\":[]},"
        "\"kind\":{\"type\":\"webhook\",\"authentication\":{\"type\":\"none\","
        "\"endpoint\":\"https://example.com/events\"}}}";
    if (bondry_egress_route_register_v1(egress, route, sizeof(route) - 1) != BONDRY_STATUS_OK) {
        return 4;
    }
    static const uint8_t route_id[] = "receiver";
    static const uint8_t delivery_id[] = "delivery_c";
    static const uint8_t payload[] = "{}";
    if (bondry_egress_emit_v1(
            egress,
            route_id,
            sizeof(route_id) - 1,
            delivery_id,
            sizeof(delivery_id) - 1,
            payload,
            sizeof(payload) - 1
        ) != BONDRY_STATUS_OK) {
        return 5;
    }

    uint8_t found = 0;
    BondryEgressDeliveryStatusV1 status = {0};
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (bondry_egress_delivery_status_v1(
                egress,
                delivery_id,
                sizeof(delivery_id) - 1,
                &found,
                &status
            ) != BONDRY_STATUS_OK) {
            return 6;
        }
        if (found == 1 && status.state == BONDRY_DELIVERY_STATE_TERMINAL_V1) {
            break;
        }
        const struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    if (status.outcome != BONDRY_DELIVERY_OUTCOME_DELIVERED_V1) {
        return 7;
    }
    if (bondry_egress_stop_v1(egress) != BONDRY_STATUS_OK ||
        bondry_store_close_v1(store) != BONDRY_STATUS_OK) {
        return 8;
    }
    return 0;
}
