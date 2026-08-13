#include "bondry.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2 || bondry_abi_version_v1() != BONDRY_ABI_VERSION_V1) {
        return 1;
    }

    uint8_t key[32];
    memset(key, 0xA5, sizeof(key));
    BondryStoreHandle *store = NULL;

    if (bondry_store_open_v1(
            (const uint8_t *)argv[1],
            strlen(argv[1]),
            key,
            sizeof(key),
            NULL
        ) != BONDRY_STATUS_NULL_POINTER) {
        return 2;
    }

    if (bondry_store_open_v1(
            (const uint8_t *)argv[1],
            strlen(argv[1]),
            key,
            sizeof(key) - 1,
            &store
        ) != BONDRY_STATUS_INVALID_LENGTH || store != NULL) {
        return 3;
    }

    const uint8_t invalid_utf8[] = {0xFF};
    if (bondry_store_open_v1(
            invalid_utf8,
            sizeof(invalid_utf8),
            key,
            sizeof(key),
            &store
        ) != BONDRY_STATUS_INVALID_UTF8 || store != NULL) {
        return 4;
    }

    if (bondry_store_open_v1(
            (const uint8_t *)"",
            0,
            key,
            sizeof(key),
            &store
        ) != BONDRY_STATUS_INVALID_PATH || store != NULL) {
        return 5;
    }

    BondryStatus status = bondry_store_open_v1(
        (const uint8_t *)argv[1],
        strlen(argv[1]),
        key,
        sizeof(key),
        &store
    );
    if (status != BONDRY_STATUS_OK || store == NULL) {
        fprintf(stderr, "open failed with status %d\n", status);
        return 6;
    }
    if (bondry_store_check_v1(store) != BONDRY_STATUS_OK) {
        return 7;
    }
    if (bondry_store_close_v1(store) != BONDRY_STATUS_OK) {
        return 8;
    }

    key[0] ^= 1;
    store = NULL;
    if (bondry_store_open_v1(
            (const uint8_t *)argv[1],
            strlen(argv[1]),
            key,
            sizeof(key),
            &store
        ) != BONDRY_STATUS_INVALID_DATABASE_KEY || store != NULL) {
        return 9;
    }
    if (bondry_store_check_v1(NULL) != BONDRY_STATUS_NULL_POINTER) {
        return 10;
    }
    if (bondry_store_close_v1(NULL) != BONDRY_STATUS_OK) {
        return 11;
    }
    return 0;
}
