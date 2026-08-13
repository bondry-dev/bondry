#include "BondryTestSupport.h"
#include "bondry.h"

#include <stdlib.h>
#include <string.h>

struct BondryStoreHandle {
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
        close_count += 1;
        free(store);
    }
    return BONDRY_STATUS_OK;
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
    *out_count = 5;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < 5) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    fill_audit(&output[0], 5, BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1, NULL);
    fill_audit(&output[1], 4, BONDRY_AUDIT_OUTCOME_DENIED_V1, "not_granted");
    fill_audit(&output[2], 3, BONDRY_AUDIT_OUTCOME_STARTED_V1, NULL);
    fill_audit(&output[3], 2, BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1, NULL);
    fill_audit(&output[4], 1, BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1, "busy");
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
    *out_count = 2;
    if (output == NULL && capacity == 0) {
        return BONDRY_STATUS_OK;
    }
    if (output == NULL || capacity < 2) {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    memset(output, 0, sizeof(*output) * 2);
    write_string(output[0].principal_id, sizeof(output[0].principal_id), "client_test");
    write_string(output[0].adapter_id, sizeof(output[0].adapter_id), "mcp");
    write_string(output[0].capability_id, sizeof(output[0].capability_id), "battery.health");
    write_string(output[1].principal_id, sizeof(output[1].principal_id), "client_test");
    write_string(output[1].adapter_id, sizeof(output[1].adapter_id), "rest");
    write_string(output[1].capability_id, sizeof(output[1].capability_id), "battery.status");
    return BONDRY_STATUS_OK;
}
