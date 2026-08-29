#ifndef BONDRY_CREDENTIALS_H
#define BONDRY_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BONDRY_CREDENTIAL_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_MAX_CREDENTIAL_ID_LENGTH_V1 ((size_t)255)
#define BONDRY_MAX_CREDENTIAL_LENGTH_V1 ((size_t)65536)

typedef int32_t BondryCredentialStatus;

#define BONDRY_CREDENTIAL_STATUS_OK ((BondryCredentialStatus)0)
#define BONDRY_CREDENTIAL_STATUS_NULL_POINTER ((BondryCredentialStatus)1)
#define BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH ((BondryCredentialStatus)2)
#define BONDRY_CREDENTIAL_STATUS_INVALID_UTF8 ((BondryCredentialStatus)3)
#define BONDRY_CREDENTIAL_STATUS_INVALID_PATH ((BondryCredentialStatus)4)
#define BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT ((BondryCredentialStatus)5)
#define BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL ((BondryCredentialStatus)6)
#define BONDRY_CREDENTIAL_STATUS_INVALID_MATERIAL ((BondryCredentialStatus)14)
#define BONDRY_CREDENTIAL_STATUS_UNAVAILABLE ((BondryCredentialStatus)15)
#define BONDRY_CREDENTIAL_STATUS_NOT_FOUND ((BondryCredentialStatus)20)
#define BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE ((BondryCredentialStatus)29)
#define BONDRY_CREDENTIAL_STATUS_ACCESS_DENIED ((BondryCredentialStatus)30)
#define BONDRY_CREDENTIAL_STATUS_READ_ONLY ((BondryCredentialStatus)31)
#define BONDRY_CREDENTIAL_STATUS_INTERNAL_FAILURE ((BondryCredentialStatus)255)

#define BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1 ((uint32_t)1)
#define BONDRY_CREDENTIAL_PROTECTION_HOST_BOUND_V1 ((uint32_t)2)
#define BONDRY_CREDENTIAL_PROTECTION_HARDWARE_BOUND_V1 ((uint32_t)3)
#define BONDRY_CREDENTIAL_PROTECTION_EXTERNAL_V1 ((uint32_t)4)

#define BONDRY_CREDENTIAL_STORE_ACCESS_READ_ONLY_V1 ((uint32_t)1)
#define BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1 ((uint32_t)2)

typedef struct BondryCredentialStoreHandle BondryCredentialStoreHandle;

typedef struct BondryCredentialStoreCapabilitiesV1 {
    uint32_t protection;
    uint32_t access;
    uint8_t supports_unattended_access;
} BondryCredentialStoreCapabilitiesV1;

uint32_t bondry_credentials_abi_version_v1(void);

/* Opens an existing absolute directory owned by the effective user with mode
 * 0700. On success, out_store must be closed exactly once. */
BondryCredentialStatus bondry_unix_file_credential_store_open_v1(
    const uint8_t *path,
    size_t path_length,
    BondryCredentialStoreHandle **out_store
);

BondryCredentialStatus bondry_credential_store_capabilities_v1(
    const BondryCredentialStoreHandle *store,
    BondryCredentialStoreCapabilitiesV1 *out_capabilities
);

/* Passing a null output with zero capacity reports the required length. */
BondryCredentialStatus bondry_credential_store_load_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    uint8_t *output,
    size_t capacity,
    size_t *out_length
);

BondryCredentialStatus bondry_credential_store_store_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    const uint8_t *value,
    size_t value_length
);

BondryCredentialStatus bondry_credential_store_delete_v1(
    const BondryCredentialStoreHandle *store,
    const uint8_t *id,
    size_t id_length,
    uint8_t *out_deleted
);

/* A non-null handle must be live and must not be used again. Null is allowed. */
BondryCredentialStatus bondry_credential_store_close_v1(
    BondryCredentialStoreHandle *store
);

#ifdef __cplusplus
}
#endif

#endif
