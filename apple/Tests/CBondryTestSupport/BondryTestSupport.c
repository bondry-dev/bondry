#include "BondryTestSupport.h"
#include "bondry.h"

#include <stdlib.h>
#include <string.h>

struct BondryStoreHandle {
    uint8_t marker;
};

struct BondryServerHandle {
    uint8_t marker;
};

static uint32_t abi_version = BONDRY_ABI_VERSION_V1;
static BondryStatus open_status = BONDRY_STATUS_OK;
static BondryStatus check_status = BONDRY_STATUS_OK;
static BondryStatus administration_status = BONDRY_STATUS_OK;
static int return_null_handle = 0;
static int client_list_growth = 0;
static size_t open_count = 0;
static size_t close_count = 0;
static size_t create_client_count = 0;
static size_t set_client_enabled_count = 0;
static size_t issue_token_count = 0;
static size_t rotate_token_count = 0;
static size_t revoke_token_count = 0;
static size_t authenticate_count = 0;
static size_t recent_audit_count = 0;
static size_t principal_audit_count = 0;
static size_t issued_token_clear_count = 0;
static size_t add_grant_count = 0;
static size_t remove_grant_count = 0;
static size_t register_capability_count = 0;
static size_t unregister_capability_count = 0;
static size_t dispatch_count = 0;
static size_t release_capability_count = 0;
static size_t captured_path_length = 0;
static size_t captured_key_length = 0;
static uint8_t captured_key[32];
static size_t captured_identifier_length = 0;
static uint8_t captured_identifier[256];
static size_t captured_label_length = 0;
static uint8_t captured_label[256];
static uint64_t captured_expiration_seconds = 0;
static uint8_t captured_has_expiration = 0;
static uint8_t captured_enabled = 0;
static size_t captured_adapter_length = 0;
static uint8_t captured_adapter[256];
static size_t captured_capability_length = 0;
static uint8_t captured_capability[256];
static size_t captured_summary_length = 0;
static uint8_t captured_summary[512];
static uint32_t captured_capability_effect = 0;
static size_t captured_input_length = 0;
static uint8_t captured_input[1024];
static uint32_t captured_principal_kind = 0;
static uint32_t dispatch_outcome = 0;
static int shortcuts_grant_mode = 0;
static BondryStatus server_start_status = BONDRY_STATUS_OK;
static BondryStatus server_stop_status = BONDRY_STATUS_OK;
static int return_null_server_handle = 0;
static int return_invalid_server_address = 0;
static size_t server_start_count = 0;
static size_t server_stop_count = 0;
static size_t captured_server_configuration_length = 0;
static uint8_t captured_server_configuration[65536];
static void *capability_context = NULL;
static BondryCapabilityInvokeV1 capability_invoke = NULL;
static BondryCapabilityReleaseV1 capability_release = NULL;
static const BondryStoreHandle *capability_store = NULL;
static int capability_registered = 0;

static void clear_capability(void) {
    if (capability_registered && capability_release != NULL) {
        capability_release(capability_context);
        release_capability_count += 1;
    }
    capability_context = NULL;
    capability_invoke = NULL;
    capability_release = NULL;
    capability_store = NULL;
    capability_registered = 0;
}

static void write_string(uint8_t *destination, size_t capacity, const char *value) {
    size_t length = strlen(value);
    if (length >= capacity) {
        length = capacity - 1;
    }
    memset(destination, 0, capacity);
    memcpy(destination, value, length);
}

static void capture_bytes(
    uint8_t *destination,
    size_t capacity,
    size_t *captured_length,
    const uint8_t *source,
    size_t source_length
) {
    *captured_length = source_length;
    memset(destination, 0, capacity);
    if (source != NULL && source_length > 0) {
        size_t copy_length = source_length < capacity ? source_length : capacity;
        memcpy(destination, source, copy_length);
    }
}

static void fill_client(BondryClientV1 *client, const char *id, const char *name, uint8_t enabled) {
    memset(client, 0, sizeof(*client));
    write_string(client->id, sizeof(client->id), id);
    write_string(client->name, sizeof(client->name), name);
    client->enabled = enabled;
    client->created_at_unix_seconds = 100;
}

static void fill_metadata(
    BondryTokenMetadataV1 *metadata,
    const char *id,
    const char *client_id,
    const char *label,
    uint8_t revoked
) {
    memset(metadata, 0, sizeof(*metadata));
    write_string(metadata->id, sizeof(metadata->id), id);
    write_string(metadata->client_id, sizeof(metadata->client_id), client_id);
    if (label != NULL) {
        write_string(metadata->label, sizeof(metadata->label), label);
        metadata->has_label = 1;
    }
    metadata->created_at_unix_seconds = 200;
    metadata->expires_at_unix_seconds = 300;
    metadata->has_expiration = 1;
    if (revoked) {
        metadata->revoked_at_unix_seconds = 250;
        metadata->has_revocation = 1;
    }
}

static void fill_audit(
    BondryAuditEventV1 *event,
    int64_t sequence,
    uint32_t outcome,
    const char *detail
) {
    memset(event, 0, sizeof(*event));
    event->sequence = sequence;
    event->occurred_at_unix_milliseconds = 400000;
    write_string(event->invocation_id, sizeof(event->invocation_id), "request_test");
    write_string(event->principal_id, sizeof(event->principal_id), "client_test");
    write_string(event->adapter_id, sizeof(event->adapter_id), "rest");
    write_string(event->capability_id, sizeof(event->capability_id), "battery.read");
    event->outcome = outcome;
    if (detail != NULL) {
        write_string(event->detail_code, sizeof(event->detail_code), detail);
        event->has_detail_code = 1;
    }
}

void bondry_test_reset(void) {
    clear_capability();
    abi_version = BONDRY_ABI_VERSION_V1;
    open_status = BONDRY_STATUS_OK;
    check_status = BONDRY_STATUS_OK;
    administration_status = BONDRY_STATUS_OK;
    return_null_handle = 0;
    client_list_growth = 0;
    open_count = 0;
    close_count = 0;
    create_client_count = 0;
    set_client_enabled_count = 0;
    issue_token_count = 0;
    rotate_token_count = 0;
    revoke_token_count = 0;
    authenticate_count = 0;
    recent_audit_count = 0;
    principal_audit_count = 0;
    issued_token_clear_count = 0;
    add_grant_count = 0;
    remove_grant_count = 0;
    register_capability_count = 0;
    unregister_capability_count = 0;
    dispatch_count = 0;
    release_capability_count = 0;
    captured_path_length = 0;
    captured_key_length = 0;
    memset(captured_key, 0, sizeof(captured_key));
    captured_identifier_length = 0;
    memset(captured_identifier, 0, sizeof(captured_identifier));
    captured_label_length = 0;
    memset(captured_label, 0, sizeof(captured_label));
    captured_expiration_seconds = 0;
    captured_has_expiration = 0;
    captured_enabled = 0;
    captured_adapter_length = 0;
    memset(captured_adapter, 0, sizeof(captured_adapter));
    captured_capability_length = 0;
    memset(captured_capability, 0, sizeof(captured_capability));
    captured_summary_length = 0;
    memset(captured_summary, 0, sizeof(captured_summary));
    captured_capability_effect = 0;
    captured_input_length = 0;
    memset(captured_input, 0, sizeof(captured_input));
    captured_principal_kind = 0;
    dispatch_outcome = 0;
    shortcuts_grant_mode = 0;
    server_start_status = BONDRY_STATUS_OK;
    server_stop_status = BONDRY_STATUS_OK;
    return_null_server_handle = 0;
    return_invalid_server_address = 0;
    server_start_count = 0;
    server_stop_count = 0;
    captured_server_configuration_length = 0;
    memset(captured_server_configuration, 0, sizeof(captured_server_configuration));
}

void bondry_test_set_abi_version(uint32_t version) {
    abi_version = version;
}

void bondry_test_set_open_status(int32_t status) {
    open_status = status;
}

void bondry_test_set_check_status(int32_t status) {
    check_status = status;
}

void bondry_test_set_null_handle(int enabled) {
    return_null_handle = enabled;
}

void bondry_test_set_administration_status(int32_t status) {
    administration_status = status;
}

void bondry_test_set_client_list_growth(int enabled) {
    client_list_growth = enabled;
}

void bondry_test_set_dispatch_outcome(uint32_t outcome) {
    dispatch_outcome = outcome;
}

void bondry_test_set_shortcuts_grant(int enabled) {
    shortcuts_grant_mode = enabled;
}

void bondry_test_set_server_start_status(int32_t status) {
    server_start_status = status;
}

void bondry_test_set_server_stop_status(int32_t status) {
    server_stop_status = status;
}

void bondry_test_set_null_server_handle(int enabled) {
    return_null_server_handle = enabled;
}

void bondry_test_set_invalid_server_address(int enabled) {
    return_invalid_server_address = enabled;
}

size_t bondry_test_open_count(void) {
    return open_count;
}

size_t bondry_test_close_count(void) {
    return close_count;
}

size_t bondry_test_create_client_count(void) {
    return create_client_count;
}

size_t bondry_test_set_client_enabled_count(void) {
    return set_client_enabled_count;
}

size_t bondry_test_issue_token_count(void) {
    return issue_token_count;
}

size_t bondry_test_rotate_token_count(void) {
    return rotate_token_count;
}

size_t bondry_test_revoke_token_count(void) {
    return revoke_token_count;
}

size_t bondry_test_authenticate_count(void) {
    return authenticate_count;
}

size_t bondry_test_recent_audit_count(void) {
    return recent_audit_count;
}

size_t bondry_test_principal_audit_count(void) {
    return principal_audit_count;
}

size_t bondry_test_issued_token_clear_count(void) {
    return issued_token_clear_count;
}

size_t bondry_test_add_grant_count(void) {
    return add_grant_count;
}

size_t bondry_test_remove_grant_count(void) {
    return remove_grant_count;
}

size_t bondry_test_register_capability_count(void) {
    return register_capability_count;
}

size_t bondry_test_unregister_capability_count(void) {
    return unregister_capability_count;
}

size_t bondry_test_dispatch_count(void) {
    return dispatch_count;
}

size_t bondry_test_release_capability_count(void) {
    return release_capability_count;
}

size_t bondry_test_server_start_count(void) {
    return server_start_count;
}

size_t bondry_test_server_stop_count(void) {
    return server_stop_count;
}

size_t bondry_test_server_configuration_length(void) {
    return captured_server_configuration_length;
}

uint8_t bondry_test_server_configuration_byte(size_t index) {
    return index < sizeof(captured_server_configuration)
        ? captured_server_configuration[index]
        : 0;
}

size_t bondry_test_path_length(void) {
    return captured_path_length;
}

size_t bondry_test_key_length(void) {
    return captured_key_length;
}

uint8_t bondry_test_key_byte(size_t index) {
    return index < sizeof(captured_key) ? captured_key[index] : 0;
}

size_t bondry_test_identifier_length(void) {
    return captured_identifier_length;
}

uint8_t bondry_test_identifier_byte(size_t index) {
    return index < sizeof(captured_identifier) ? captured_identifier[index] : 0;
}

size_t bondry_test_label_length(void) {
    return captured_label_length;
}

uint8_t bondry_test_label_byte(size_t index) {
    return index < sizeof(captured_label) ? captured_label[index] : 0;
}

uint64_t bondry_test_expiration_seconds(void) {
    return captured_expiration_seconds;
}

uint8_t bondry_test_has_expiration(void) {
    return captured_has_expiration;
}

uint8_t bondry_test_enabled(void) {
    return captured_enabled;
}

size_t bondry_test_adapter_length(void) {
    return captured_adapter_length;
}

uint8_t bondry_test_adapter_byte(size_t index) {
    return index < sizeof(captured_adapter) ? captured_adapter[index] : 0;
}

size_t bondry_test_capability_length(void) {
    return captured_capability_length;
}

uint8_t bondry_test_capability_byte(size_t index) {
    return index < sizeof(captured_capability) ? captured_capability[index] : 0;
}

size_t bondry_test_summary_length(void) {
    return captured_summary_length;
}

uint8_t bondry_test_summary_byte(size_t index) {
    return index < sizeof(captured_summary) ? captured_summary[index] : 0;
}

uint32_t bondry_test_capability_effect(void) {
    return captured_capability_effect;
}

size_t bondry_test_input_length(void) {
    return captured_input_length;
}

uint8_t bondry_test_input_byte(size_t index) {
    return index < sizeof(captured_input) ? captured_input[index] : 0;
}

uint32_t bondry_test_principal_kind(void) {
    return captured_principal_kind;
}

uint32_t bondry_abi_version_v1(void) {
    return abi_version;
}

BondryStatus bondry_store_open_v1(
    const uint8_t *path,
    size_t path_length,
    const uint8_t *key,
    size_t key_length,
    BondryStoreHandle **out_store
) {
    open_count += 1;
    captured_path_length = path_length;
    captured_key_length = key_length;
    if (key != NULL && key_length == sizeof(captured_key)) {
        memcpy(captured_key, key, sizeof(captured_key));
    }
    if (out_store != NULL) {
        *out_store = NULL;
    }
    if (open_status != BONDRY_STATUS_OK || out_store == NULL) {
        return open_status;
    }
    if (return_null_handle) {
        return BONDRY_STATUS_OK;
    }

    BondryStoreHandle *store = malloc(sizeof(BondryStoreHandle));
    if (store == NULL) {
        return BONDRY_STATUS_INTERNAL_FAILURE;
    }
    store->marker = path == NULL ? 0 : 1;
    *out_store = store;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_store_check_v1(const BondryStoreHandle *store) {
    return store == NULL ? BONDRY_STATUS_NULL_POINTER : check_status;
}

BondryStatus bondry_store_close_v1(BondryStoreHandle *store) {
    if (store != NULL) {
        if (store == capability_store) {
            clear_capability();
        }
        close_count += 1;
        free(store);
    }
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_server_start_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    BondryServerHandle **out_server,
    BondryServerAddressV1 *out_address
) {
    server_start_count += 1;
    capture_bytes(
        captured_server_configuration,
        sizeof(captured_server_configuration),
        &captured_server_configuration_length,
        configuration_json,
        configuration_json_length
    );
    if (out_server != NULL) {
        *out_server = NULL;
    }
    if (out_address != NULL) {
        memset(out_address, 0, sizeof(*out_address));
    }
    if (server_start_status != BONDRY_STATUS_OK) {
        return server_start_status;
    }
    if (store == NULL || configuration_json == NULL || out_server == NULL ||
        out_address == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    if (return_null_server_handle) {
        return BONDRY_STATUS_OK;
    }
    BondryServerHandle *server = malloc(sizeof(*server));
    if (server == NULL) {
        return BONDRY_STATUS_INTERNAL_FAILURE;
    }
    server->marker = 1;
    *out_server = server;
    if (return_invalid_server_address) {
        out_address->address[0] = 0xFF;
    } else {
        write_string(out_address->address, sizeof(out_address->address), "127.0.0.1");
    }
    out_address->port = 54321;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_server_stop_v1(BondryServerHandle *server) {
    if (server != NULL) {
        server_stop_count += 1;
        free(server);
    }
    return server_stop_status;
}

BondryStatus bondry_client_create_v1(
    const BondryStoreHandle *store,
    const uint8_t *name,
    size_t name_length,
    BondryClientV1 *out_client
) {
    create_client_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        name,
        name_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_client == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    fill_client(out_client, "client_created", "Created Client", 1);
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_clients_list_v1(
    const BondryStoreHandle *store,
    BondryClientV1 *output,
    size_t capacity,
    size_t *out_count
) {
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_count == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    if (output == NULL && capacity == 0) {
        *out_count = 2;
        return BONDRY_STATUS_OK;
    }
    if (client_list_growth) {
        client_list_growth = 0;
        *out_count = 3;
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    size_t required = 2;
    if (capacity >= 3) {
        required = 3;
    }
    *out_count = required;
    if (output == NULL || capacity < required) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    fill_client(&output[0], "client_a", "First", 1);
    fill_client(&output[1], "client_b", "Second", 0);
    if (required == 3) {
        fill_client(&output[2], "client_c", "Third", 1);
    }
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_client_set_enabled_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    uint8_t enabled
) {
    set_client_enabled_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        client_id,
        client_id_length
    );
    captured_enabled = enabled;
    return store == NULL ? BONDRY_STATUS_NULL_POINTER : administration_status;
}

static BondryStatus issue_token(
    const BondryStoreHandle *store,
    const uint8_t *identifier,
    size_t identifier_length,
    const uint8_t *label,
    size_t label_length,
    uint64_t expires_in_seconds,
    uint8_t has_expiration,
    BondryIssuedTokenV1 *out_token,
    int rotate
) {
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        identifier,
        identifier_length
    );
    capture_bytes(
        captured_label,
        sizeof(captured_label),
        &captured_label_length,
        label,
        label_length
    );
    captured_expiration_seconds = expires_in_seconds;
    captured_has_expiration = has_expiration;
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_token == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    memset(out_token, 0, sizeof(*out_token));
    fill_metadata(
        &out_token->metadata,
        rotate ? "token_replacement" : "token_issued",
        "client_test",
        label == NULL ? NULL : "Primary",
        0
    );
    write_string(
        out_token->secret,
        sizeof(out_token->secret),
        rotate ? "bondry_v1.token_replacement.secret" : "bondry_v1.token_issued.secret"
    );
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_token_issue_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    const uint8_t *label,
    size_t label_length,
    uint64_t expires_in_seconds,
    uint8_t has_expiration,
    BondryIssuedTokenV1 *out_token
) {
    issue_token_count += 1;
    return issue_token(
        store,
        client_id,
        client_id_length,
        label,
        label_length,
        expires_in_seconds,
        has_expiration,
        out_token,
        0
    );
}

BondryStatus bondry_token_rotate_v1(
    const BondryStoreHandle *store,
    const uint8_t *token_id,
    size_t token_id_length,
    const uint8_t *label,
    size_t label_length,
    uint64_t expires_in_seconds,
    uint8_t has_expiration,
    BondryIssuedTokenV1 *out_token
) {
    rotate_token_count += 1;
    return issue_token(
        store,
        token_id,
        token_id_length,
        label,
        label_length,
        expires_in_seconds,
        has_expiration,
        out_token,
        1
    );
}

BondryStatus bondry_token_revoke_v1(
    const BondryStoreHandle *store,
    const uint8_t *token_id,
    size_t token_id_length,
    uint8_t *out_changed
) {
    revoke_token_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        token_id,
        token_id_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_changed == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    *out_changed = 1;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_tokens_list_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    BondryTokenMetadataV1 *output,
    size_t capacity,
    size_t *out_count
) {
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        client_id,
        client_id_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_count == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    *out_count = 2;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < 2) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    fill_metadata(&output[0], "token_active", "client_test", "Primary", 0);
    fill_metadata(&output[1], "token_revoked", "client_test", NULL, 1);
    output[1].expires_at_unix_seconds = 0;
    output[1].has_expiration = 0;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_token_authenticate_v1(
    const BondryStoreHandle *store,
    const uint8_t *token,
    size_t token_length,
    BondryPrincipalV1 *out_principal
) {
    authenticate_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        token,
        token_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_principal == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    memset(out_principal, 0, sizeof(*out_principal));
    write_string(out_principal->id, sizeof(out_principal->id), "client_authenticated");
    out_principal->kind = BONDRY_PRINCIPAL_KIND_APPLICATION_V1;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_issued_token_clear_v1(BondryIssuedTokenV1 *token) {
    if (token != NULL) {
        issued_token_clear_count += 1;
        memset(token, 0, sizeof(*token));
    }
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_audit_recent_v1(
    const BondryStoreHandle *store,
    uint32_t limit,
    BondryAuditEventV1 *output,
    size_t capacity,
    size_t *out_count
) {
    recent_audit_count += 1;
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_count == NULL || limit == 0) {
        return BONDRY_STATUS_INVALID_ARGUMENT;
    }
    *out_count = 6;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < 6) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    fill_audit(&output[0], 6, BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1, NULL);
    fill_audit(&output[1], 5, BONDRY_AUDIT_OUTCOME_DENIED_V1, "not_granted");
    fill_audit(&output[2], 4, BONDRY_AUDIT_OUTCOME_STARTED_V1, NULL);
    fill_audit(&output[3], 3, BONDRY_AUDIT_OUTCOME_INVALID_INPUT_V1, NULL);
    fill_audit(&output[4], 2, BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1, NULL);
    fill_audit(&output[5], 1, BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1, "busy");
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_audit_for_principal_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    uint32_t limit,
    BondryAuditEventV1 *output,
    size_t capacity,
    size_t *out_count
) {
    principal_audit_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        principal_id,
        principal_id_length
    );
    return bondry_audit_recent_v1(store, limit, output, capacity, out_count);
}

static BondryStatus update_grant(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
) {
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        principal_id,
        principal_id_length
    );
    capture_bytes(
        captured_adapter,
        sizeof(captured_adapter),
        &captured_adapter_length,
        adapter_id,
        adapter_id_length
    );
    capture_bytes(
        captured_capability,
        sizeof(captured_capability),
        &captured_capability_length,
        capability_id,
        capability_id_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_changed == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    *out_changed = 1;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_grant_add_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
) {
    add_grant_count += 1;
    return update_grant(
        store,
        principal_id,
        principal_id_length,
        adapter_id,
        adapter_id_length,
        capability_id,
        capability_id_length,
        out_changed
    );
}

BondryStatus bondry_grant_remove_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
) {
    remove_grant_count += 1;
    return update_grant(
        store,
        principal_id,
        principal_id_length,
        adapter_id,
        adapter_id_length,
        capability_id,
        capability_id_length,
        out_changed
    );
}

BondryStatus bondry_grants_list_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    BondryGrantV1 *output,
    size_t capacity,
    size_t *out_count
) {
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        principal_id,
        principal_id_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_count == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    size_t count = shortcuts_grant_mode ? 3 : 2;
    *out_count = count;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < count) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    memset(output, 0, sizeof(*output) * count);
    write_string(output[0].principal_id, sizeof(output[0].principal_id), "client_test");
    write_string(output[0].adapter_id, sizeof(output[0].adapter_id), "mcp");
    write_string(output[0].capability_id, sizeof(output[0].capability_id), "battery.health");
    write_string(output[1].principal_id, sizeof(output[1].principal_id), "client_test");
    write_string(output[1].adapter_id, sizeof(output[1].adapter_id), "rest");
    write_string(output[1].capability_id, sizeof(output[1].capability_id), "battery.status");
    if (shortcuts_grant_mode) {
        write_string(
            output[2].principal_id,
            sizeof(output[2].principal_id),
            shortcuts_grant_mode == 1 ? "shortcuts.local-user" : "shortcuts.other-user"
        );
        write_string(output[2].adapter_id, sizeof(output[2].adapter_id), "shortcuts");
        write_string(output[2].capability_id, sizeof(output[2].capability_id), "battery.read");
    }
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_capability_register_v1(
    const BondryStoreHandle *store,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *summary,
    size_t summary_length,
    uint32_t effect,
    void *handler_context,
    BondryCapabilityInvokeV1 invoke,
    BondryCapabilityReleaseV1 release
) {
    register_capability_count += 1;
    capture_bytes(
        captured_capability,
        sizeof(captured_capability),
        &captured_capability_length,
        capability_id,
        capability_id_length
    );
    capture_bytes(
        captured_summary,
        sizeof(captured_summary),
        &captured_summary_length,
        summary,
        summary_length
    );
    captured_capability_effect = effect;
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || capability_id == NULL || summary == NULL || invoke == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    if (capability_registered) {
        return BONDRY_STATUS_ALREADY_EXISTS;
    }
    capability_context = handler_context;
    capability_invoke = invoke;
    capability_release = release;
    capability_store = store;
    capability_registered = 1;
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_capability_unregister_v1(
    const BondryStoreHandle *store,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
) {
    unregister_capability_count += 1;
    capture_bytes(
        captured_capability,
        sizeof(captured_capability),
        &captured_capability_length,
        capability_id,
        capability_id_length
    );
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || capability_id == NULL || out_changed == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    *out_changed = capability_registered ? 1 : 0;
    clear_capability();
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_capabilities_list_v1(
    const BondryStoreHandle *store,
    BondryCapabilityV1 *output,
    size_t capacity,
    size_t *out_count
) {
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || out_count == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    *out_count = capability_registered ? 1 : 0;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (!capability_registered) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < 1) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    memset(output, 0, sizeof(*output));
    write_string(output->id, sizeof(output->id), "battery.read");
    write_string(output->summary, sizeof(output->summary), "Read battery state");
    output->effect = captured_capability_effect;
    return BONDRY_STATUS_OK;
}

typedef struct DispatchBridge {
    BondryDispatchCompletionV1 completion;
    void *context;
} DispatchBridge;

static void complete_handler(
    void *completion_context,
    uint32_t outcome,
    const uint8_t *payload,
    size_t payload_length
) {
    DispatchBridge *bridge = completion_context;
    BondryDispatchResultV1 result;
    memset(&result, 0, sizeof(result));
    if (outcome == BONDRY_HANDLER_RESULT_SUCCEEDED_V1) {
        result.outcome = BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1;
        result.output_json = payload;
        result.output_json_length = payload_length;
    } else if (outcome == BONDRY_HANDLER_RESULT_FAILED_V1) {
        result.outcome = BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1;
        size_t length = payload_length < sizeof(result.detail_code) - 1
            ? payload_length
            : sizeof(result.detail_code) - 1;
        if (payload != NULL) {
            memcpy(result.detail_code, payload, length);
        }
        result.has_detail_code = 1;
    } else {
        result.outcome = BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1;
        write_string(result.detail_code, sizeof(result.detail_code), "invalid_handler_result");
        result.has_detail_code = 1;
    }
    bridge->completion(bridge->context, &result);
    free(bridge);
}

static void complete_forced_dispatch(
    BondryDispatchCompletionV1 completion,
    void *completion_context
) {
    BondryDispatchResultV1 result;
    memset(&result, 0, sizeof(result));
    result.outcome = dispatch_outcome;
    if (dispatch_outcome == BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1) {
        write_string(result.detail_code, sizeof(result.detail_code), "not_granted");
        result.has_detail_code = 1;
    } else if (dispatch_outcome == BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1) {
        write_string(result.detail_code, sizeof(result.detail_code), "busy");
        result.has_detail_code = 1;
    }
    completion(completion_context, &result);
}

static void write_bytes(
    uint8_t *destination,
    size_t capacity,
    const uint8_t *source,
    size_t source_length
) {
    memset(destination, 0, capacity);
    if (source != NULL && source_length > 0) {
        size_t length = source_length < capacity - 1 ? source_length : capacity - 1;
        memcpy(destination, source, length);
    }
}

static BondryStatus dispatch_test(
    const BondryStoreHandle *store,
    const uint8_t *invocation_id,
    size_t invocation_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *principal_id,
    size_t principal_id_length,
    uint32_t principal_kind,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *input_json,
    size_t input_json_length,
    BondryDispatchCompletionV1 completion,
    void *completion_context
) {
    capture_bytes(
        captured_adapter,
        sizeof(captured_adapter),
        &captured_adapter_length,
        adapter_id,
        adapter_id_length
    );
    capture_bytes(
        captured_capability,
        sizeof(captured_capability),
        &captured_capability_length,
        capability_id,
        capability_id_length
    );
    capture_bytes(
        captured_input,
        sizeof(captured_input),
        &captured_input_length,
        input_json,
        input_json_length
    );
    captured_principal_kind = principal_kind;
    if (administration_status != BONDRY_STATUS_OK) {
        return administration_status;
    }
    if (store == NULL || invocation_id == NULL || invocation_id_length == 0 ||
        adapter_id == NULL || principal_id == NULL || capability_id == NULL ||
        input_json == NULL || completion == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    if (dispatch_outcome != 0) {
        complete_forced_dispatch(completion, completion_context);
        return BONDRY_STATUS_OK;
    }
    if (!capability_registered || capability_invoke == NULL) {
        BondryDispatchResultV1 result;
        memset(&result, 0, sizeof(result));
        result.outcome = BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1;
        completion(completion_context, &result);
        return BONDRY_STATUS_OK;
    }
    DispatchBridge *bridge = malloc(sizeof(*bridge));
    if (bridge == NULL) {
        return BONDRY_STATUS_INTERNAL_FAILURE;
    }
    bridge->completion = completion;
    bridge->context = completion_context;
    BondryInvocationV1 invocation;
    memset(&invocation, 0, sizeof(invocation));
    write_bytes(
        invocation.invocation_id,
        sizeof(invocation.invocation_id),
        invocation_id,
        invocation_id_length
    );
    write_bytes(
        invocation.principal_id,
        sizeof(invocation.principal_id),
        principal_id,
        principal_id_length
    );
    invocation.principal_kind = principal_kind;
    write_bytes(
        invocation.adapter_id,
        sizeof(invocation.adapter_id),
        adapter_id,
        adapter_id_length
    );
    write_bytes(
        invocation.capability_id,
        sizeof(invocation.capability_id),
        capability_id,
        capability_id_length
    );
    invocation.input_json = input_json;
    invocation.input_json_length = input_json_length;
    capability_invoke(capability_context, &invocation, complete_handler, bridge);
    return BONDRY_STATUS_OK;
}

BondryStatus bondry_dispatch_token_v1(
    const BondryStoreHandle *store,
    const uint8_t *invocation_id,
    size_t invocation_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *token,
    size_t token_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *input_json,
    size_t input_json_length,
    BondryDispatchCompletionV1 completion,
    void *completion_context
) {
    dispatch_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        token,
        token_length
    );
    if (token == NULL) {
        return BONDRY_STATUS_NULL_POINTER;
    }
    return dispatch_test(
        store,
        (const uint8_t *)"request_test",
        12,
        adapter_id,
        adapter_id_length,
        (const uint8_t *)"client_test",
        11,
        BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
        capability_id,
        capability_id_length,
        input_json,
        input_json_length,
        completion,
        completion_context
    );
}

BondryStatus bondry_dispatch_principal_v1(
    const BondryStoreHandle *store,
    const uint8_t *invocation_id,
    size_t invocation_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *principal_id,
    size_t principal_id_length,
    uint32_t principal_kind,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *input_json,
    size_t input_json_length,
    BondryDispatchCompletionV1 completion,
    void *completion_context
) {
    dispatch_count += 1;
    capture_bytes(
        captured_identifier,
        sizeof(captured_identifier),
        &captured_identifier_length,
        principal_id,
        principal_id_length
    );
    return dispatch_test(
        store,
        invocation_id,
        invocation_id_length,
        adapter_id,
        adapter_id_length,
        principal_id,
        principal_id_length,
        principal_kind,
        capability_id,
        capability_id_length,
        input_json,
        input_json_length,
        completion,
        completion_context
    );
}
