#ifndef BONDRY_EGRESS_H
#define BONDRY_EGRESS_H

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
#define BONDRY_STATUS_BUFFER_TOO_SMALL ((BondryStatus)6)
#define BONDRY_STATUS_INVALID_JSON ((BondryStatus)7)
#define BONDRY_STATUS_PAYLOAD_TOO_LARGE ((BondryStatus)8)
#define BONDRY_STATUS_INVALID_DATA ((BondryStatus)14)
#define BONDRY_STATUS_UNAVAILABLE ((BondryStatus)15)
#define BONDRY_STATUS_NOT_FOUND ((BondryStatus)20)
#define BONDRY_STATUS_ALREADY_EXISTS ((BondryStatus)28)
#define BONDRY_STATUS_CAPACITY_EXHAUSTED ((BondryStatus)32)
#define BONDRY_STATUS_INTERNAL_FAILURE ((BondryStatus)255)

#define BONDRY_IDENTIFIER_CAPACITY_V1 ((size_t)129)

#define BONDRY_DELIVERY_STATE_PENDING_V1 ((uint32_t)1)
#define BONDRY_DELIVERY_STATE_TERMINAL_V1 ((uint32_t)2)

#define BONDRY_DELIVERY_OUTCOME_NONE_V1 ((uint32_t)0)
#define BONDRY_DELIVERY_OUTCOME_DELIVERED_V1 ((uint32_t)1)
#define BONDRY_DELIVERY_OUTCOME_FAILED_V1 ((uint32_t)2)
#define BONDRY_DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1 ((uint32_t)3)
#define BONDRY_DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1 ((uint32_t)4)

#define BONDRY_DELIVERY_FAILURE_NONE_V1 ((uint32_t)0)
#define BONDRY_DELIVERY_FAILURE_CANCELLED_V1 ((uint32_t)1)
#define BONDRY_DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1 ((uint32_t)2)
#define BONDRY_DELIVERY_FAILURE_ENDPOINT_POLICY_V1 ((uint32_t)3)
#define BONDRY_DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1 ((uint32_t)4)
#define BONDRY_DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1 ((uint32_t)5)
#define BONDRY_DELIVERY_FAILURE_RECEIVER_REJECTED_V1 ((uint32_t)6)
#define BONDRY_DELIVERY_FAILURE_RETRY_EXHAUSTED_V1 ((uint32_t)7)
#define BONDRY_DELIVERY_FAILURE_INTERNAL_V1 ((uint32_t)8)

#define BONDRY_DELIVERY_RESULT_NONE_V1 ((uint32_t)0)
#define BONDRY_DELIVERY_RESULT_SUCCEEDED_V1 ((uint32_t)1)
#define BONDRY_DELIVERY_RESULT_FAILED_V1 ((uint32_t)2)
#define BONDRY_DELIVERY_RESULT_INVALID_V1 ((uint32_t)3)

#define BONDRY_EGRESS_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_SECRET_PROVIDER_ABI_VERSION_V1 ((uint32_t)1)

#define BONDRY_EGRESS_MAX_RUNTIME_CONFIGURATION_BYTES_V1 ((size_t)65536)
#define BONDRY_EGRESS_MAX_ROUTE_CONFIGURATION_BYTES_V1 ((size_t)131072)
#define BONDRY_EGRESS_MAX_EVENT_PAYLOAD_BYTES_V1 ((size_t)229376)

#define BONDRY_STATUS_EGRESS_START_FAILED ((BondryStatus)34)
#define BONDRY_STATUS_EGRESS_STOP_FAILED ((BondryStatus)35)
#define BONDRY_STATUS_EGRESS_BUSY ((BondryStatus)36)
#define BONDRY_STATUS_EGRESS_STOPPED ((BondryStatus)37)
#define BONDRY_STATUS_EGRESS_ROUTE_DRAINING ((BondryStatus)38)
#define BONDRY_STATUS_EGRESS_PENDING_CAPACITY ((BondryStatus)39)
#define BONDRY_STATUS_EGRESS_PENDING_BYTES ((BondryStatus)40)
#define BONDRY_STATUS_EGRESS_GLOBAL_RATE_LIMITED ((BondryStatus)41)
#define BONDRY_STATUS_EGRESS_ROUTE_RATE_LIMITED ((BondryStatus)42)
#define BONDRY_STATUS_EGRESS_ROUTE_DISABLED ((BondryStatus)43)
#define BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION ((BondryStatus)44)
#define BONDRY_STATUS_EGRESS_DELIVERY_LOG ((BondryStatus)45)

#define BONDRY_HTTP_RESULT_RESPONSE_V1 ((uint32_t)1)
#define BONDRY_HTTP_RESULT_ERROR_V1 ((uint32_t)2)

#define BONDRY_CONNECTION_EVIDENCE_MISSING_V1 ((uint32_t)0)
#define BONDRY_CONNECTION_EVIDENCE_TLS_V1 ((uint32_t)1)
#define BONDRY_CONNECTION_EVIDENCE_CLEARTEXT_V1 ((uint32_t)2)

#define BONDRY_IP_ADDRESS_V4_V1 ((uint32_t)1)
#define BONDRY_IP_ADDRESS_V6_V1 ((uint32_t)2)

#define BONDRY_TRANSPORT_ERROR_INVALID_LIMITS_V1 ((uint32_t)1)
#define BONDRY_TRANSPORT_ERROR_UNSUPPORTED_ENDPOINT_V1 ((uint32_t)2)
#define BONDRY_TRANSPORT_ERROR_REQUEST_TOO_LARGE_V1 ((uint32_t)3)
#define BONDRY_TRANSPORT_ERROR_RESPONSE_TOO_LARGE_V1 ((uint32_t)4)
#define BONDRY_TRANSPORT_ERROR_MISSING_EVIDENCE_V1 ((uint32_t)5)
#define BONDRY_TRANSPORT_ERROR_EVIDENCE_MISMATCH_V1 ((uint32_t)6)
#define BONDRY_TRANSPORT_ERROR_TLS_IDENTITY_MISMATCH_V1 ((uint32_t)7)
#define BONDRY_TRANSPORT_ERROR_LOOPBACK_INTENT_REQUIRED_V1 ((uint32_t)8)
#define BONDRY_TRANSPORT_ERROR_PRIVATE_CLEARTEXT_DENIED_V1 ((uint32_t)9)
#define BONDRY_TRANSPORT_ERROR_LINK_LOCAL_CLEARTEXT_DENIED_V1 ((uint32_t)10)
#define BONDRY_TRANSPORT_ERROR_LINK_LOCAL_SCOPE_REQUIRED_V1 ((uint32_t)11)
#define BONDRY_TRANSPORT_ERROR_CLEARTEXT_DENIED_V1 ((uint32_t)12)
#define BONDRY_TRANSPORT_ERROR_REDIRECT_DENIED_V1 ((uint32_t)13)
#define BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1 ((uint32_t)14)
#define BONDRY_TRANSPORT_ERROR_CONNECTION_FAILED_V1 ((uint32_t)15)
#define BONDRY_TRANSPORT_ERROR_TLS_FAILED_V1 ((uint32_t)16)
#define BONDRY_TRANSPORT_ERROR_INVALID_RESPONSE_V1 ((uint32_t)17)
#define BONDRY_TRANSPORT_ERROR_INVALID_MESSAGE_V1 ((uint32_t)18)

typedef struct BondryEgressHandle BondryEgressHandle;
typedef struct BondryStoreHandle BondryStoreHandle;

typedef struct BondryByteSliceV1 {
    const uint8_t *bytes;
    size_t length;
} BondryByteSliceV1;

typedef struct BondryHTTPHeaderV1 {
    const uint8_t *name;
    size_t name_length;
    const uint8_t *value;
    size_t value_length;
} BondryHTTPHeaderV1;

typedef struct BondryEndpointPolicyV1 {
    uint8_t allow_hostname_loopback_cleartext;
    uint8_t allow_private_cleartext;
    uint8_t allow_link_local_cleartext;
    const BondryByteSliceV1 *additional_trust_anchors;
    size_t additional_trust_anchor_count;
} BondryEndpointPolicyV1;

typedef struct BondryHTTPRequestV1 {
    const uint8_t *method;
    size_t method_length;
    const uint8_t *url;
    size_t url_length;
    const BondryHTTPHeaderV1 *headers;
    size_t header_count;
    const uint8_t *body;
    size_t body_length;
    uint64_t timeout_milliseconds;
    size_t max_response_body_bytes;
    BondryEndpointPolicyV1 policy;
} BondryHTTPRequestV1;

typedef struct BondryConnectionEvidenceV1 {
    uint32_t kind;
    const uint8_t *server_name;
    size_t server_name_length;
    uint32_t ip_family;
    uint8_t ip[16];
    uint16_t port;
    uint32_t interface_scope;
    uint8_t has_interface_scope;
} BondryConnectionEvidenceV1;

typedef struct BondryHTTPResultV1 {
    uint32_t kind;
    uint32_t error;
    uint16_t status_code;
    const BondryHTTPHeaderV1 *headers;
    size_t header_count;
    const uint8_t *body;
    size_t body_length;
    BondryConnectionEvidenceV1 connection;
} BondryHTTPResultV1;

typedef void *(*BondryContextRetainV1)(void *context);
typedef void (*BondryContextReleaseV1)(void *context);
typedef void (*BondryHTTPCompletionV1)(
    void *completion_context,
    const BondryHTTPResultV1 *result
);
typedef BondryStatus (*BondryHTTPSendV1)(
    void *transport_context,
    const BondryHTTPRequestV1 *request,
    BondryHTTPCompletionV1 completion,
    void *completion_context
);

typedef struct BondryHTTPTransportV1 {
    uint32_t abi_version;
    size_t struct_size;
    void *context;
    BondryContextRetainV1 retain;
    BondryContextReleaseV1 release;
    BondryHTTPSendV1 send;
} BondryHTTPTransportV1;

typedef void (*BondrySecretResolutionV1)(
    void *completion_context,
    const uint8_t *current,
    size_t current_length,
    const uint8_t *previous,
    size_t previous_length,
    uint8_t has_previous
);
typedef BondryStatus (*BondrySecretResolveV1)(
    void *provider_context,
    const uint8_t *secret_reference,
    size_t secret_reference_length,
    BondrySecretResolutionV1 completion,
    void *completion_context
);

typedef struct BondrySecretProviderV1 {
    uint32_t abi_version;
    size_t struct_size;
    void *context;
    BondryContextRetainV1 retain;
    BondryContextReleaseV1 release;
    BondrySecretResolveV1 resolve;
} BondrySecretProviderV1;

typedef struct BondryEgressDeliveryStatusV1 {
    uint8_t route_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t delivery_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint64_t accepted_at_unix_ms;
    uint64_t updated_at_unix_ms;
    uint16_t attempts;
    uint32_t state;
    uint32_t outcome;
    uint32_t failure;
    uint32_t result_category;
    uint32_t result_bytes;
} BondryEgressDeliveryStatusV1;

uint32_t bondry_egress_abi_version_v1(void);

/* The descriptors and store remain caller-owned. Start synchronously retains one
 * context unit from each descriptor and derives its own delivery-log unit. */
BondryStatus bondry_egress_start_v1(
    const BondryStoreHandle *store,
    const uint8_t *runtime_configuration_json,
    size_t runtime_configuration_json_length,
    const BondryHTTPTransportV1 *transport,
    const BondrySecretProviderV1 *secrets,
    BondryEgressHandle **out_egress
);

/* Stop is exclusive, drains for the configured deadline, and consumes the handle
 * even when it reports an error. Null is allowed. */
BondryStatus bondry_egress_stop_v1(BondryEgressHandle *egress);

/* Operations may run concurrently, but never concurrently with stop. Input
 * buffers are borrowed only for each call. Disable and unregister wait for the
 * configured bounded drain. */
BondryStatus bondry_egress_route_register_v1(
    const BondryEgressHandle *egress,
    const uint8_t *configuration_json,
    size_t configuration_json_length
);
BondryStatus bondry_egress_route_enable_v1(
    const BondryEgressHandle *egress,
    const uint8_t *route_id,
    size_t route_id_length
);
BondryStatus bondry_egress_route_disable_v1(
    const BondryEgressHandle *egress,
    const uint8_t *route_id,
    size_t route_id_length
);
BondryStatus bondry_egress_route_unregister_v1(
    const BondryEgressHandle *egress,
    const uint8_t *route_id,
    size_t route_id_length
);

/* A null output with zero capacity returns the required JSON byte length. Route
 * summaries contain only identifier, enabled state, kind, and redacted target. */
BondryStatus bondry_egress_routes_json_v1(
    const BondryEgressHandle *egress,
    uint8_t *output_json,
    size_t capacity,
    size_t *out_length
);

BondryStatus bondry_egress_emit_v1(
    const BondryEgressHandle *egress,
    const uint8_t *route_id,
    size_t route_id_length,
    const uint8_t *delivery_id,
    size_t delivery_id_length,
    const uint8_t *payload_json,
    size_t payload_json_length
);

BondryStatus bondry_egress_delivery_status_v1(
    const BondryEgressHandle *egress,
    const uint8_t *delivery_id,
    size_t delivery_id_length,
    uint8_t *out_found,
    BondryEgressDeliveryStatusV1 *out_status
);

/* Descriptor retain, release, send, resolve, and completion callbacks must be
 * thread-safe and must not unwind. Request fields are borrowed only until send
 * returns. An accepted send must call completion exactly once, including after a
 * timeout; a rejected send must never call it. Completion fields are borrowed only
 * for that callback. The transport must disable redirects, enforce the supplied
 * endpoint policy against the effective connection, retain ordinary TLS identity
 * and validity checks when adding trust anchors, and report connection evidence.
 * Bondry independently verifies that evidence before accepting the response. */

/* Secret resolution is synchronous. A successful resolve must invoke completion
 * exactly once before returning; an unsuccessful resolve must not invoke it.
 * Secret bytes are borrowed only for the completion call and are copied into
 * bounded zeroizing Rust storage before resolve returns. */

#ifdef __cplusplus
}
#endif

#endif
