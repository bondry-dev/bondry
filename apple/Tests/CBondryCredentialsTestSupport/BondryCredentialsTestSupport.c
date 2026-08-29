#include "BondryCredentialsTestSupport.h"
#include "bondry_credentials.h"

#include <stdlib.h>
#include <string.h>

struct BondryCredentialStoreHandle {
    uint8_t marker;
};

static uint32_t abi_version = BONDRY_CREDENTIAL_ABI_VERSION_V1;
static BondryCredentialStatus open_status = BONDRY_CREDENTIAL_STATUS_OK;
static BondryCredentialStoreCapabilitiesV1 capabilities;
static uint8_t credential[BONDRY_MAX_CREDENTIAL_LENGTH_V1];
static size_t credential_length = 0;
static int grow_next_load = 0;
static uint8_t growth_byte = 0;
static size_t open_count = 0;
static size_t close_count = 0;

void bondry_credentials_test_reset(void) {
    abi_version = BONDRY_CREDENTIAL_ABI_VERSION_V1;
    open_status = BONDRY_CREDENTIAL_STATUS_OK;
    capabilities.protection = BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1;
    capabilities.access = BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1;
    capabilities.supports_unattended_access = 1;
    memset(credential, 0, sizeof(credential));
    credential_length = 0;
    grow_next_load = 0;
    growth_byte = 0;
    open_count = 0;
    close_count = 0;
}

void bondry_credentials_test_grow_next_load(uint8_t appended_byte) {
    grow_next_load = 1;
    growth_byte = appended_byte;
}

void bondry_credentials_test_set_abi_version(uint32_t version) {
    abi_version = version;
}

void bondry_credentials_test_set_open_status(int32_t status) {
    open_status = status;
}

void bondry_credentials_test_set_capabilities(
    uint32_t protection,
    uint32_t access,
    uint8_t supports_unattended_access
) {
    capabilities.protection = protection;
    capabilities.access = access;
    capabilities.supports_unattended_access = supports_unattended_access;
}

size_t bondry_credentials_test_open_count(void) {
    return open_count;
}

size_t bondry_credentials_test_close_count(void) {
    return close_count;
}

uint32_t bondry_credentials_abi_version_v1(void) {
    return abi_version;
}

BondryCredentialStatus bondry_unix_file_credential_store_open_v1(
    const uint8_t *path,
    size_t path_length,
    BondryCredentialStoreHandle **out_store
) {
    if (out_store == NULL) {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    *out_store = NULL;
    if (open_status != BONDRY_CREDENTIAL_STATUS_OK) {
        return open_status;
    }
    if (path == NULL || path_length == 0) {
        return BONDRY_CREDENTIAL_STATUS_INVALID_PATH;
    }
    BondryCredentialStoreHandle *store = malloc(sizeof(*store));
    if (store == NULL) {
        return BONDRY_CREDENTIAL_STATUS_UNAVAILABLE;
    }
    store->marker = 1;
    *out_store = store;
    open_count += 1;
    return BONDRY_CREDENTIAL_STATUS_OK;
}

BondryCredentialStatus bondry_credential_store_capabilities_v1(
    const BondryCredentialStoreHandle *store,
    BondryCredentialStoreCapabilitiesV1 *out_capabilities
) {
    if (store == NULL || out_capabilities == NULL) {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    *out_capabilities = capabilities;
    return BONDRY_CREDENTIAL_STATUS_OK;
}

BondryCredentialStatus bondry_credential_store_load_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    uint8_t *output,
    size_t capacity,
    size_t *out_length
) {
    if (store == NULL || id == NULL || out_length == NULL) {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    if (id_length == 0) {
        return BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT;
    }
    *out_length = credential_length;
    if (credential_length == 0) {
        return BONDRY_CREDENTIAL_STATUS_NOT_FOUND;
    }
    if (output == NULL) {
        return capacity == 0 ? BONDRY_CREDENTIAL_STATUS_OK
                             : BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    if (grow_next_load && credential_length < sizeof(credential)) {
        credential[credential_length] = growth_byte;
        credential_length += 1;
        *out_length = credential_length;
        grow_next_load = 0;
    }
    if (capacity < credential_length) {
        return BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(output, credential, credential_length);
    return BONDRY_CREDENTIAL_STATUS_OK;
}

BondryCredentialStatus bondry_credential_store_store_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    const uint8_t *value,
    size_t value_length
) {
    if (store == NULL || id == NULL || value == NULL) {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    if (id_length == 0 || value_length == 0 || value_length > sizeof(credential)) {
        return BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH;
    }
    memcpy(credential, value, value_length);
    credential_length = value_length;
    return BONDRY_CREDENTIAL_STATUS_OK;
}

BondryCredentialStatus bondry_credential_store_delete_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    uint8_t *out_deleted
) {
    if (store == NULL || id == NULL || out_deleted == NULL) {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    if (id_length == 0) {
        return BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT;
    }
    *out_deleted = credential_length > 0 ? 1 : 0;
    memset(credential, 0, credential_length);
    credential_length = 0;
    return BONDRY_CREDENTIAL_STATUS_OK;
}

BondryCredentialStatus bondry_credential_store_close_v1(BondryCredentialStoreHandle *store) {
    if (store != NULL) {
        memset(store, 0, sizeof(*store));
        free(store);
        close_count += 1;
    }
    return BONDRY_CREDENTIAL_STATUS_OK;
}
