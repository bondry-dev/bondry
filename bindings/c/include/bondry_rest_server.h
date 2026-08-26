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

typedef struct BondryStoreHandle BondryStoreHandle;
typedef struct BondryRestServerHandle BondryRestServerHandle;

typedef struct BondryRestServerAddressV1 {
    uint8_t address[BONDRY_REST_SERVER_ADDRESS_CAPACITY_V1];
    uint16_t port;
} BondryRestServerAddressV1;

BondryStatus bondry_rest_server_start_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    BondryRestServerHandle **out_server,
    BondryRestServerAddressV1 *out_address
);

BondryStatus bondry_rest_server_stop_v1(BondryRestServerHandle *server);

#ifdef __cplusplus
}
#endif

#endif
