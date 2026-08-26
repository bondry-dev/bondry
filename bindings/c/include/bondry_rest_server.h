#ifndef BONDRY_REST_SERVER_H
#define BONDRY_REST_SERVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t BondryStatus;

#define BONDRY_STATUS_OK ((BondryStatus)0)
#define BONDRY_STATUS_NULL_POINTER ((BondryStatus)1)
#define BONDRY_STATUS_INVALID_LENGTH ((BondryStatus)2)
#define BONDRY_STATUS_INVALID_ARGUMENT ((BondryStatus)5)
#define BONDRY_STATUS_INVALID_JSON ((BondryStatus)7)
#define BONDRY_STATUS_PAYLOAD_TOO_LARGE ((BondryStatus)8)
#define BONDRY_STATUS_SERVER_BIND ((BondryStatus)29)
#define BONDRY_STATUS_SERVER_START ((BondryStatus)30)
#define BONDRY_STATUS_SERVER_STOP ((BondryStatus)31)
#define BONDRY_STATUS_INTERNAL_FAILURE ((BondryStatus)255)

#define BONDRY_REST_SERVER_ADDRESS_CAPACITY_V1 ((size_t)46)
#define BONDRY_REST_SERVER_CONFIGURATION_VERSION_V1 ((uint32_t)1)
#define BONDRY_REST_TLS_SERVER_CONFIGURATION_VERSION_V1 ((uint32_t)1)
#define BONDRY_REST_TLS_IDENTITY_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_REST_TLS_CERTIFICATE_COUNT_V1 ((size_t)16)
#define BONDRY_REST_TLS_CERTIFICATE_CHAIN_BYTES_V1 ((size_t)262144)
#define BONDRY_REST_TLS_PRIVATE_KEY_BYTES_V1 ((size_t)65536)
#define BONDRY_REST_UNIX_SERVER_CONFIGURATION_VERSION_V1 ((uint32_t)1)
#define BONDRY_REST_UNIX_SERVER_PATH_CAPACITY_V1 ((size_t)104)

typedef struct BondryStoreHandle BondryStoreHandle;
typedef struct BondryRestServerHandle BondryRestServerHandle;
typedef struct BondryRestUnixServerHandle BondryRestUnixServerHandle;

typedef struct BondryRestTLSByteSliceV1 {
    const uint8_t *bytes;
    size_t length;
} BondryRestTLSByteSliceV1;

typedef struct BondryRestTLSIdentityV1 {
    uint32_t abi_version;
    size_t struct_size;
    const BondryRestTLSByteSliceV1 *certificate_chain;
    size_t certificate_count;
    const uint8_t *private_key_pkcs8;
    size_t private_key_pkcs8_length;
} BondryRestTLSIdentityV1;

typedef struct BondryRestServerAddressV1 {
    uint8_t address[BONDRY_REST_SERVER_ADDRESS_CAPACITY_V1];
    uint16_t port;
} BondryRestServerAddressV1;

typedef struct BondryRestUnixServerEndpointV1 {
    uint8_t path[BONDRY_REST_UNIX_SERVER_PATH_CAPACITY_V1];
} BondryRestUnixServerEndpointV1;

BondryStatus bondry_rest_server_start_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    BondryRestServerHandle **out_server,
    BondryRestServerAddressV1 *out_address
);

BondryStatus bondry_rest_server_stop_v1(BondryRestServerHandle *server);

/* Identity buffers are borrowed only for this call. The implementation copies
 * and clears temporary private-key material after constructing the server. */
BondryStatus bondry_rest_server_start_tls_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    const BondryRestTLSIdentityV1 *identity,
    BondryRestServerHandle **out_server,
    BondryRestServerAddressV1 *out_address
);

BondryStatus bondry_rest_server_start_unix_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    BondryRestUnixServerHandle **out_server,
    BondryRestUnixServerEndpointV1 *out_endpoint
);

BondryStatus bondry_rest_server_stop_unix_v1(BondryRestUnixServerHandle *server);

#ifdef __cplusplus
}
#endif

#endif
