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

    BondryClientV1 client;
    memset(&client, 0xFF, sizeof(client));
    if (bondry_client_create_v1(
            store,
            (const uint8_t *)"Smoke Client",
            strlen("Smoke Client"),
            &client
        ) != BONDRY_STATUS_OK || strcmp((const char *)client.name, "Smoke Client") != 0) {
        return 8;
    }

    size_t client_count = 0;
    if (bondry_clients_list_v1(store, NULL, 0, &client_count) != BONDRY_STATUS_OK ||
        client_count != 1) {
        return 9;
    }
    BondryClientV1 clients[1];
    if (bondry_clients_list_v1(store, clients, 1, &client_count) != BONDRY_STATUS_OK ||
        strcmp((const char *)clients[0].id, (const char *)client.id) != 0) {
        return 10;
    }

    uint8_t grant_changed = 0;
    if (bondry_grant_add_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            (const uint8_t *)"rest",
            strlen("rest"),
            (const uint8_t *)"battery.read",
            strlen("battery.read"),
            &grant_changed
        ) != BONDRY_STATUS_OK || grant_changed != 1) {
        return 30;
    }
    size_t grant_count = 0;
    if (bondry_grants_list_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            NULL,
            0,
            &grant_count
        ) != BONDRY_STATUS_OK || grant_count != 1) {
        return 31;
    }
    BondryGrantV1 grants[1];
    if (bondry_grants_list_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            grants,
            1,
            &grant_count
        ) != BONDRY_STATUS_OK ||
        strcmp((const char *)grants[0].adapter_id, "rest") != 0 ||
        strcmp((const char *)grants[0].capability_id, "battery.read") != 0) {
        return 32;
    }
    if (bondry_grant_remove_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            (const uint8_t *)"rest",
            strlen("rest"),
            (const uint8_t *)"battery.read",
            strlen("battery.read"),
            &grant_changed
        ) != BONDRY_STATUS_OK || grant_changed != 1) {
        return 33;
    }

    BondryIssuedTokenV1 issued;
    memset(&issued, 0xFF, sizeof(issued));
    if (bondry_token_issue_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            (const uint8_t *)"Primary",
            strlen("Primary"),
            3600,
            1,
            &issued
        ) != BONDRY_STATUS_OK ||
        strncmp((const char *)issued.secret, "bondry_v1.token_", strlen("bondry_v1.token_")) != 0 ||
        issued.metadata.has_label != 1 || issued.metadata.has_expiration != 1) {
        return 11;
    }

    uint8_t original_secret[BONDRY_TOKEN_CAPACITY_V1];
    uint8_t original_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    memcpy(original_secret, issued.secret, sizeof(original_secret));
    memcpy(original_id, issued.metadata.id, sizeof(original_id));
    BondryPrincipalV1 principal;
    if (bondry_token_authenticate_v1(
            store,
            original_secret,
            strlen((const char *)original_secret),
            &principal
        ) != BONDRY_STATUS_OK ||
        principal.kind != BONDRY_PRINCIPAL_KIND_APPLICATION_V1 ||
        strcmp((const char *)principal.id, (const char *)client.id) != 0) {
        return 12;
    }

    if (bondry_client_set_enabled_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            0
        ) != BONDRY_STATUS_OK ||
        bondry_token_authenticate_v1(
            store,
            original_secret,
            strlen((const char *)original_secret),
            &principal
        ) != BONDRY_STATUS_AUTHENTICATION_REJECTED ||
        bondry_client_set_enabled_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            1
        ) != BONDRY_STATUS_OK) {
        return 13;
    }

    BondryIssuedTokenV1 replacement;
    if (bondry_token_rotate_v1(
            store,
            original_id,
            strlen((const char *)original_id),
            NULL,
            0,
            0,
            0,
            &replacement
        ) != BONDRY_STATUS_OK ||
        bondry_token_authenticate_v1(
            store,
            original_secret,
            strlen((const char *)original_secret),
            &principal
        ) != BONDRY_STATUS_AUTHENTICATION_REJECTED) {
        return 14;
    }

    size_t token_count = 0;
    if (bondry_tokens_list_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            NULL,
            0,
            &token_count
        ) != BONDRY_STATUS_OK || token_count != 2) {
        return 15;
    }
    BondryTokenMetadataV1 tokens[2];
    if (bondry_tokens_list_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            tokens,
            1,
            &token_count
        ) != BONDRY_STATUS_BUFFER_TOO_SMALL || token_count != 2) {
        return 16;
    }
    if (bondry_tokens_list_v1(
            store,
            client.id,
            strlen((const char *)client.id),
            tokens,
            2,
            &token_count
        ) != BONDRY_STATUS_OK) {
        return 17;
    }

    uint8_t changed = 0;
    if (bondry_token_revoke_v1(
            store,
            replacement.metadata.id,
            strlen((const char *)replacement.metadata.id),
            &changed
        ) != BONDRY_STATUS_OK || changed != 1) {
        return 18;
    }
    if (bondry_issued_token_clear_v1(&replacement) != BONDRY_STATUS_OK ||
        replacement.secret[0] != 0 || replacement.metadata.id[0] != 0) {
        return 19;
    }

    size_t audit_count = 99;
    if (bondry_audit_recent_v1(store, 10, NULL, 0, &audit_count) != BONDRY_STATUS_OK ||
        audit_count != 0) {
        return 20;
    }
    if (bondry_store_close_v1(store) != BONDRY_STATUS_OK) {
        return 21;
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
        return 22;
    }
    if (bondry_store_check_v1(NULL) != BONDRY_STATUS_NULL_POINTER) {
        return 23;
    }
    if (bondry_store_close_v1(NULL) != BONDRY_STATUS_OK) {
        return 24;
    }
    return 0;
}
