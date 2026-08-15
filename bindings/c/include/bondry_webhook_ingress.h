#ifndef BONDRY_WEBHOOK_INGRESS_H
#define BONDRY_WEBHOOK_INGRESS_H

#if defined(__has_include)
#if __has_include(<CBondryRuntime/bondry.h>) && \
    __has_include(<CBondryLocalServer/bondry_local_server.h>)
#include <CBondryLocalServer/bondry_local_server.h>
#include <CBondryRuntime/bondry.h>
#else
#include "bondry.h"
#include "bondry_local_server.h"
#endif
#else
#include "bondry.h"
#include "bondry_local_server.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1 ((uint32_t)1)
#define BONDRY_WEBHOOK_MAX_CONFIGURATION_BYTES_V1 ((size_t)65536)

typedef void (*BondryWebhookSecretResolutionV1)(
    void *completion_context,
    const uint8_t *current,
    size_t current_length,
    const uint8_t *previous,
    size_t previous_length,
    uint8_t has_previous
);
typedef BondryStatus (*BondryWebhookSecretResolveV1)(
    void *provider_context,
    const uint8_t *secret_reference,
    size_t secret_reference_length,
    BondryWebhookSecretResolutionV1 completion,
    void *completion_context
);

typedef struct BondryWebhookSecretProviderV1 {
    uint32_t abi_version;
    size_t struct_size;
    void *context;
    BondryContextRetainV1 retain;
    BondryContextReleaseV1 release;
    BondryWebhookSecretResolveV1 resolve;
} BondryWebhookSecretProviderV1;

typedef struct BondryWebhookIngressRegistrationDescriptorV1 {
    uint32_t abi_version;
    size_t struct_size;
    const uint8_t *configuration_json;
    size_t configuration_json_length;
    BondryAutomationServiceV1 automation;
    BondryDedupStoreV1 dedup;
    BondryWebhookSecretProviderV1 secrets;
} BondryWebhookIngressRegistrationDescriptorV1;

uint32_t bondry_webhook_ingress_abi_version_v1(void);

/* The registration descriptor and JSON are borrowed only for this call. Every
 * host service is synchronously retained for one immutable handler generation.
 * On success out_handler owns one context unit. */
BondryStatus bondry_webhook_ingress_handler_v1(
    const BondryWebhookIngressRegistrationDescriptorV1 *descriptor,
    BondryRawBodyHandlerDescriptorV1 *out_handler
);

/* Releases the creator-owned context unit and zeros the descriptor. Call this
 * exactly once after local-server registration succeeds or fails. The local
 * server's independently retained generation remains valid. Null is allowed. */
void bondry_webhook_ingress_handler_release_v1(
    BondryRawBodyHandlerDescriptorV1 *handler
);

/* Route configuration JSON version 1:
 * {
 *   "version": 1,
 *   "routeId": "stable.route",
 *   "path": "/opaque-path",
 *   "principal": {"id": "host.principal", "kind": "application"},
 *   "capabilityId": "fixed.capability",
 *   "semantics": "read_only|idempotent_mutation|non_idempotent_mutation",
 *   "verifier": {
 *     "type": "bearer|bondry_hmac_sha256|github_hmac_sha256|stripe_hmac_sha256",
 *     "secretRef": "provider:reference",
 *     "toleranceSeconds": 300
 *   },
 *   "mapping": {"type": "json_body"},
 *   "successStatus": 204
 * }
 * HMAC tolerance is 30 through 900 seconds. Optional limits use camelCase names
 * from the published ingress limits contract, including selectedHeaders (default
 * 16, maximum 32); omitted values use its defaults. Configuration never contains
 * secret material. */

#ifdef __cplusplus
}
#endif

#endif
