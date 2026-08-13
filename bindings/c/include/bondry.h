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
#define BONDRY_STATUS_INVALID_ARGUMENT ((BondryStatus)5)
#define BONDRY_STATUS_BUFFER_TOO_SMALL ((BondryStatus)6)
#define BONDRY_STATUS_INVALID_JSON ((BondryStatus)7)
#define BONDRY_STATUS_PAYLOAD_TOO_LARGE ((BondryStatus)8)
#define BONDRY_STATUS_FILE_SYSTEM ((BondryStatus)10)
#define BONDRY_STATUS_DATABASE ((BondryStatus)11)
#define BONDRY_STATUS_UNSUPPORTED_SCHEMA ((BondryStatus)12)
#define BONDRY_STATUS_INVALID_DATABASE_KEY ((BondryStatus)13)
#define BONDRY_STATUS_INVALID_DATA ((BondryStatus)14)
#define BONDRY_STATUS_UNAVAILABLE ((BondryStatus)15)
#define BONDRY_STATUS_NOT_FOUND ((BondryStatus)20)
#define BONDRY_STATUS_CLIENT_DISABLED ((BondryStatus)21)
#define BONDRY_STATUS_TOKEN_INACTIVE ((BondryStatus)22)
#define BONDRY_STATUS_AUTHENTICATION_REJECTED ((BondryStatus)23)
#define BONDRY_STATUS_INVALID_TOKEN_LIFETIME ((BondryStatus)24)
#define BONDRY_STATUS_ENTROPY_UNAVAILABLE ((BondryStatus)25)
#define BONDRY_STATUS_TIME_UNAVAILABLE ((BondryStatus)26)
#define BONDRY_STATUS_GENERATION_EXHAUSTED ((BondryStatus)27)
#define BONDRY_STATUS_ALREADY_EXISTS ((BondryStatus)28)
#define BONDRY_STATUS_INTERNAL_FAILURE ((BondryStatus)255)

#define BONDRY_IDENTIFIER_CAPACITY_V1 ((size_t)129)
#define BONDRY_LABEL_CAPACITY_V1 ((size_t)129)
#define BONDRY_TOKEN_CAPACITY_V1 ((size_t)100)
#define BONDRY_AUDIT_DETAIL_CAPACITY_V1 ((size_t)129)
#define BONDRY_CAPABILITY_SUMMARY_CAPACITY_V1 ((size_t)257)
#define BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1 ((size_t)1048576)

#define BONDRY_PRINCIPAL_KIND_USER_V1 ((uint32_t)1)
#define BONDRY_PRINCIPAL_KIND_APPLICATION_V1 ((uint32_t)2)
#define BONDRY_PRINCIPAL_KIND_SYSTEM_V1 ((uint32_t)3)

#define BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1 ((uint32_t)1)
#define BONDRY_AUDIT_OUTCOME_DENIED_V1 ((uint32_t)2)
#define BONDRY_AUDIT_OUTCOME_STARTED_V1 ((uint32_t)3)
#define BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1 ((uint32_t)4)
#define BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1 ((uint32_t)5)
#define BONDRY_AUDIT_OUTCOME_INVALID_INPUT_V1 ((uint32_t)6)

#define BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1 ((uint32_t)1)
#define BONDRY_CAPABILITY_EFFECT_MUTATING_V1 ((uint32_t)2)

#define BONDRY_HANDLER_RESULT_SUCCEEDED_V1 ((uint32_t)1)
#define BONDRY_HANDLER_RESULT_FAILED_V1 ((uint32_t)2)

#define BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1 ((uint32_t)1)
#define BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1 ((uint32_t)2)
#define BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1 ((uint32_t)3)
#define BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1 ((uint32_t)4)
#define BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1 ((uint32_t)5)
#define BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1 ((uint32_t)6)

typedef struct BondryStoreHandle BondryStoreHandle;

typedef struct BondryClientV1 {
    uint8_t id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t name[BONDRY_LABEL_CAPACITY_V1];
    uint8_t enabled;
    int64_t created_at_unix_seconds;
} BondryClientV1;

typedef struct BondryTokenMetadataV1 {
    uint8_t id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t client_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t label[BONDRY_LABEL_CAPACITY_V1];
    uint8_t has_label;
    int64_t created_at_unix_seconds;
    int64_t expires_at_unix_seconds;
    uint8_t has_expiration;
    int64_t revoked_at_unix_seconds;
    uint8_t has_revocation;
} BondryTokenMetadataV1;

typedef struct BondryIssuedTokenV1 {
    BondryTokenMetadataV1 metadata;
    uint8_t secret[BONDRY_TOKEN_CAPACITY_V1];
} BondryIssuedTokenV1;

typedef struct BondryPrincipalV1 {
    uint8_t id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint32_t kind;
} BondryPrincipalV1;

typedef struct BondryGrantV1 {
    uint8_t principal_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t adapter_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t capability_id[BONDRY_IDENTIFIER_CAPACITY_V1];
} BondryGrantV1;

typedef struct BondryAuditEventV1 {
    int64_t sequence;
    int64_t occurred_at_unix_milliseconds;
    uint8_t invocation_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t principal_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t adapter_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t capability_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint32_t outcome;
    uint8_t detail_code[BONDRY_AUDIT_DETAIL_CAPACITY_V1];
    uint8_t has_detail_code;
} BondryAuditEventV1;

typedef struct BondryCapabilityV1 {
    uint8_t id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t summary[BONDRY_CAPABILITY_SUMMARY_CAPACITY_V1];
    uint32_t effect;
} BondryCapabilityV1;

typedef struct BondryInvocationV1 {
    uint8_t invocation_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t principal_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint32_t principal_kind;
    uint8_t adapter_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    uint8_t capability_id[BONDRY_IDENTIFIER_CAPACITY_V1];
    const uint8_t *input_json;
    size_t input_json_length;
} BondryInvocationV1;

typedef struct BondryDispatchResultV1 {
    uint32_t outcome;
    const uint8_t *output_json;
    size_t output_json_length;
    uint8_t detail_code[BONDRY_AUDIT_DETAIL_CAPACITY_V1];
    uint8_t has_detail_code;
} BondryDispatchResultV1;

typedef void (*BondryCapabilityCompletionV1)(
    void *completion_context,
    uint32_t outcome,
    const uint8_t *payload,
    size_t payload_length
);

typedef void (*BondryCapabilityInvokeV1)(
    void *handler_context,
    const BondryInvocationV1 *invocation,
    BondryCapabilityCompletionV1 completion,
    void *completion_context
);

typedef void (*BondryCapabilityReleaseV1)(void *handler_context);

typedef void (*BondryDispatchCompletionV1)(
    void *completion_context,
    const BondryDispatchResultV1 *result
);

/* Caller-owned output records and count pointers must not overlap one another. */

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

BondryStatus bondry_client_create_v1(
    const BondryStoreHandle *store,
    const uint8_t *name,
    size_t name_length,
    BondryClientV1 *out_client
);

/* Passing a null output with zero capacity returns the required count. */
BondryStatus bondry_clients_list_v1(
    const BondryStoreHandle *store,
    BondryClientV1 *output,
    size_t capacity,
    size_t *out_count
);

BondryStatus bondry_client_set_enabled_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    uint8_t enabled
);

/* A null label with zero length means no label. Expiration is present only when
 * has_expiration is one and expires_in_seconds is nonzero. */
BondryStatus bondry_token_issue_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    const uint8_t *label,
    size_t label_length,
    uint64_t expires_in_seconds,
    uint8_t has_expiration,
    BondryIssuedTokenV1 *out_token
);

BondryStatus bondry_token_rotate_v1(
    const BondryStoreHandle *store,
    const uint8_t *token_id,
    size_t token_id_length,
    const uint8_t *label,
    size_t label_length,
    uint64_t expires_in_seconds,
    uint8_t has_expiration,
    BondryIssuedTokenV1 *out_token
);

BondryStatus bondry_token_revoke_v1(
    const BondryStoreHandle *store,
    const uint8_t *token_id,
    size_t token_id_length,
    uint8_t *out_changed
);

/* Passing a null output with zero capacity returns the required count. */
BondryStatus bondry_tokens_list_v1(
    const BondryStoreHandle *store,
    const uint8_t *client_id,
    size_t client_id_length,
    BondryTokenMetadataV1 *output,
    size_t capacity,
    size_t *out_count
);

/* The credential remains caller-owned and is never retained by Bondry. */
BondryStatus bondry_token_authenticate_v1(
    const BondryStoreHandle *store,
    const uint8_t *token,
    size_t token_length,
    BondryPrincipalV1 *out_principal
);

/* Clears the one-time secret and all metadata in a caller-owned record. */
BondryStatus bondry_issued_token_clear_v1(BondryIssuedTokenV1 *token);

/* Limits must be between 1 and 1000. Passing a null output with zero capacity
 * returns the result count, which may be lower than the requested limit. */
BondryStatus bondry_audit_recent_v1(
    const BondryStoreHandle *store,
    uint32_t limit,
    BondryAuditEventV1 *output,
    size_t capacity,
    size_t *out_count
);

BondryStatus bondry_audit_for_principal_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    uint32_t limit,
    BondryAuditEventV1 *output,
    size_t capacity,
    size_t *out_count
);

BondryStatus bondry_grant_add_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
);

BondryStatus bondry_grant_remove_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
);

/* Passing a null output with zero capacity returns the required count. */
BondryStatus bondry_grants_list_v1(
    const BondryStoreHandle *store,
    const uint8_t *principal_id,
    size_t principal_id_length,
    BondryGrantV1 *output,
    size_t capacity,
    size_t *out_count
);

/* Registration transfers handler_context ownership only on success. Invoke and
 * release may run on any thread and must not unwind across the ABI. Invocation
 * fields and input_json are borrowed only until invoke returns. The handler must
 * copy anything needed asynchronously and call completion exactly once. A
 * successful result payload is JSON; a failed result payload is a stable,
 * non-sensitive error code. Handler completion payloads are borrowed for that
 * completion call and must not exceed BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1 bytes. */
BondryStatus bondry_capability_register_v1(
    const BondryStoreHandle *store,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *summary,
    size_t summary_length,
    uint32_t effect,
    void *handler_context,
    BondryCapabilityInvokeV1 invoke,
    BondryCapabilityReleaseV1 release
);

/* In-flight invocations keep the handler context alive after unregistration. */
BondryStatus bondry_capability_unregister_v1(
    const BondryStoreHandle *store,
    const uint8_t *capability_id,
    size_t capability_id_length,
    uint8_t *out_changed
);

/* Passing a null output with zero capacity returns the required count. */
BondryStatus bondry_capabilities_list_v1(
    const BondryStoreHandle *store,
    BondryCapabilityV1 *output,
    size_t capacity,
    size_t *out_count
);

/* On BONDRY_STATUS_OK, completion is called exactly once and may run before
 * this function returns or later on any thread. Result pointers are borrowed
 * only for that callback. Immediate errors never call completion and leave its
 * context caller-owned. Credentials and JSON payloads are never retained or
 * written to the audit log. */
BondryStatus bondry_dispatch_token_v1(
    const BondryStoreHandle *store,
    const uint8_t *invocation_id,
    size_t invocation_id_length,
    const uint8_t *adapter_id,
    size_t adapter_id_length,
    const uint8_t *token,
    size_t token_length,
    const uint8_t *capability_id,
    size_t capability_id_length,
    const uint8_t *input_json,
    size_t input_json_length,
    BondryDispatchCompletionV1 completion,
    void *completion_context
);

#ifdef __cplusplus
}
#endif

#endif
