#ifndef BONDRY_H
#define BONDRY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BONDRY_ABI_VERSION_V1 ((uint32_t)1)

typedef int32_t BondryStatus;

#define BONDRY_STATUS_OK ((BondryStatus)0)
#define BONDRY_STATUS_NULL_POINTER ((BondryStatus)1)
#define BONDRY_STATUS_INVALID_LENGTH ((BondryStatus)2)
#define BONDRY_STATUS_INVALID_UTF8 ((BondryStatus)3)
#define BONDRY_STATUS_INVALID_PATH ((BondryStatus)4)
#define BONDRY_STATUS_FILE_SYSTEM ((BondryStatus)10)
#define BONDRY_STATUS_DATABASE ((BondryStatus)11)
#define BONDRY_STATUS_UNSUPPORTED_SCHEMA ((BondryStatus)12)
#define BONDRY_STATUS_INVALID_DATABASE_KEY ((BondryStatus)13)
#define BONDRY_STATUS_INVALID_DATA ((BondryStatus)14)
#define BONDRY_STATUS_UNAVAILABLE ((BondryStatus)15)
#define BONDRY_STATUS_INTERNAL_FAILURE ((BondryStatus)255)

typedef struct BondryStoreHandle BondryStoreHandle;

uint32_t bondry_abi_version_v1(void);

/* Input buffers must remain readable for the duration of this call. On success,
 * out_store owns one handle that must be passed exactly once to close. */
BondryStatus bondry_store_open_v1(
    const uint8_t *path,
    size_t path_length,
    const uint8_t *key,
    size_t key_length,
    BondryStoreHandle **out_store
);

/* The handle must remain live and must not be closed concurrently. */
BondryStatus bondry_store_check_v1(const BondryStoreHandle *store);

/* A non-null handle must be live and must not be used again. Null is allowed. */
BondryStatus bondry_store_close_v1(BondryStoreHandle *store);

#ifdef __cplusplus
}
#endif

#endif
