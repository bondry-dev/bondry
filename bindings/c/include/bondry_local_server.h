#ifndef BONDRY_LOCAL_SERVER_H
#define BONDRY_LOCAL_SERVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t BondryStatus;

#define BONDRY_STATUS_OK ((BondryStatus)0)
#define BONDRY_STATUS_NULL_POINTER ((BondryStatus)1)
#define BONDRY_STATUS_INVALID_LENGTH ((BondryStatus)2)
#define BONDRY_STATUS_INVALID_UTF8 ((BondryStatus)3)
#define BONDRY_STATUS_INVALID_ARGUMENT ((BondryStatus)5)
#define BONDRY_STATUS_INVALID_JSON ((BondryStatus)7)
#define BONDRY_STATUS_PAYLOAD_TOO_LARGE ((BondryStatus)8)
#define BONDRY_STATUS_ALREADY_EXISTS ((BondryStatus)28)
#define BONDRY_STATUS_SERVER_BIND ((BondryStatus)29)
#define BONDRY_STATUS_SERVER_START ((BondryStatus)30)
#define BONDRY_STATUS_SERVER_STOP ((BondryStatus)31)
#define BONDRY_STATUS_CAPACITY_EXHAUSTED ((BondryStatus)32)
#define BONDRY_STATUS_INVALID_TRANSITION ((BondryStatus)33)
#define BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT ((BondryStatus)60)
#define BONDRY_STATUS_INTERNAL_FAILURE ((BondryStatus)255)

#define BONDRY_SERVER_ADDRESS_CAPACITY_V1 ((size_t)46)
#define BONDRY_SERVER_CONFIGURATION_VERSION_V1 ((uint32_t)1)
#define BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1 ((uint32_t)1)

#define BONDRY_RAW_BODY_METHOD_POST_V1 ((uint32_t)1)

#define BONDRY_RAW_BODY_LIFECYCLE_ENABLED_V1 ((uint32_t)1)
#define BONDRY_RAW_BODY_LIFECYCLE_DRAINING_V1 ((uint32_t)2)
#define BONDRY_RAW_BODY_LIFECYCLE_DETACHED_V1 ((uint32_t)3)

#define BONDRY_RAW_BODY_IP_ADDRESS_V4_V1 ((uint32_t)1)
#define BONDRY_RAW_BODY_IP_ADDRESS_V6_V1 ((uint32_t)2)

typedef struct BondryStoreHandle BondryStoreHandle;
typedef struct BondryServerHandle BondryServerHandle;
typedef struct BondryRawBodyRegistrationHandle BondryRawBodyRegistrationHandle;

typedef struct BondryServerAddressV1 {
    uint8_t address[BONDRY_SERVER_ADDRESS_CAPACITY_V1];
    uint16_t port;
} BondryServerAddressV1;

typedef struct BondryRawBodyByteSliceV1 {
    const uint8_t *bytes;
    size_t length;
} BondryRawBodyByteSliceV1;

typedef struct BondryRawBodyHeaderV1 {
    const uint8_t *name;
    size_t name_length;
    const uint8_t *value;
    size_t value_length;
} BondryRawBodyHeaderV1;

typedef struct BondryRawBodyRequestV1 {
    uint32_t abi_version;
    size_t struct_size;
    const uint8_t *target;
    size_t target_length;
    const BondryRawBodyHeaderV1 *headers;
    size_t header_count;
    const uint8_t *body;
    size_t body_length;
    uint32_t peer_ip_family;
    uint8_t peer_ip[16];
    uint16_t peer_port;
    uint32_t peer_interface_scope;
    uint8_t has_peer_interface_scope;
} BondryRawBodyRequestV1;

typedef struct BondryRawBodyResponseV1 {
    uint32_t abi_version;
    size_t struct_size;
    uint16_t status_code;
    uint64_t retry_after_seconds;
    uint8_t has_retry_after;
} BondryRawBodyResponseV1;

typedef void *(*BondryRawBodyContextRetainV1)(void *context);
typedef void (*BondryRawBodyContextReleaseV1)(void *context);
typedef void (*BondryRawBodyCompletionV1)(
    void *completion_context,
    const BondryRawBodyResponseV1 *response
);
typedef void (*BondryRawBodyHandleV1)(
    void *handler_context,
    const BondryRawBodyRequestV1 *request,
    BondryRawBodyCompletionV1 completion,
    void *completion_context
);

typedef struct BondryRawBodyHandlerDescriptorV1 {
    uint32_t abi_version;
    size_t struct_size;
    uint32_t method;
    BondryRawBodyByteSliceV1 path;
    const BondryRawBodyByteSliceV1 *selected_headers;
    size_t selected_header_count;
    size_t max_body_bytes;
    size_t max_retained_bytes;
    size_t max_selected_header_bytes;
    size_t max_selected_headers_bytes;
    uint32_t pre_authentication_requests_per_peer_minute;
    uint32_t pre_authentication_requests_per_route_minute;
    void *context;
    BondryRawBodyContextRetainV1 retain;
    BondryRawBodyContextReleaseV1 release;
    BondryRawBodyHandleV1 handle;
} BondryRawBodyHandlerDescriptorV1;

/* On success, the server retains the runtime state it needs and owns one
 * handle that must be passed exactly once to stop. */
BondryStatus bondry_server_start_v1(
    const BondryStoreHandle *store,
    const uint8_t *configuration_json,
    size_t configuration_json_length,
    BondryServerHandle **out_server,
    BondryServerAddressV1 *out_address
);

/* A non-null handle must be live and must not be used again. Null is allowed. */
BondryStatus bondry_server_stop_v1(BondryServerHandle *server);

/* The descriptor and its buffers are borrowed only for this call. Registration
 * synchronously retains one context unit. Serialize registration with server stop. */
BondryStatus bondry_server_raw_body_handler_register_v1(
    const BondryServerHandle *server,
    const BondryRawBodyHandlerDescriptorV1 *descriptor,
    BondryRawBodyRegistrationHandle **out_registration
);

/* Disable closes admission atomically, then blocks for a bounded drain. A timeout
 * leaves the generation draining and never force-releases its context. Do not call
 * disable from the generation's own handler callback. */
BondryStatus bondry_server_raw_body_handler_disable_v1(
    const BondryRawBodyRegistrationHandle *registration,
    uint64_t deadline_milliseconds
);

BondryStatus bondry_server_raw_body_handler_lifecycle_v1(
    const BondryRawBodyRegistrationHandle *registration,
    uint32_t *out_lifecycle
);

/* Release consumes the handle and closes admission. Accepted work retains the
 * generation until its asynchronous completions finish. */
void bondry_server_raw_body_handler_release_v1(
    BondryRawBodyRegistrationHandle *registration
);

/* Handler retain, release, handle, and completion callbacks must be thread-safe
 * and must not unwind. Request fields are borrowed only until handle returns and
 * must be copied before asynchronous use. Handle owns one completion unit and must
 * invoke it exactly once, including after an HTTP timeout or disconnect. Response
 * fields are borrowed only for the completion callback. Release runs exactly once
 * after Detached and never while a completion remains active. */

#ifdef __cplusplus
}
#endif

#endif
