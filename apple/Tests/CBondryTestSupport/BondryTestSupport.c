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
static int return_null_handle = 0;
static size_t open_count = 0;
static size_t close_count = 0;
static size_t captured_path_length = 0;
static size_t captured_key_length = 0;
static uint8_t captured_key[32];

void bondry_test_reset(void) {
    abi_version = BONDRY_ABI_VERSION_V1;
    open_status = BONDRY_STATUS_OK;
    check_status = BONDRY_STATUS_OK;
    return_null_handle = 0;
    open_count = 0;
    close_count = 0;
    captured_path_length = 0;
    captured_key_length = 0;
    memset(captured_key, 0, sizeof(captured_key));
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

size_t bondry_test_open_count(void) {
    return open_count;
}

size_t bondry_test_close_count(void) {
    return close_count;
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
