#ifndef BONDRY_TEST_SUPPORT_H
#define BONDRY_TEST_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

void bondry_test_reset(void);
void bondry_test_set_abi_version(uint32_t version);
void bondry_test_set_open_status(int32_t status);
void bondry_test_set_check_status(int32_t status);
void bondry_test_set_null_handle(int enabled);
void bondry_test_set_administration_status(int32_t status);
void bondry_test_set_client_list_growth(int enabled);
void bondry_test_set_dispatch_outcome(uint32_t outcome);
void bondry_test_set_shortcuts_grant(int enabled);
void bondry_test_set_server_start_status(int32_t status);
void bondry_test_set_server_stop_status(int32_t status);
void bondry_test_set_null_server_handle(int enabled);
void bondry_test_set_invalid_server_address(int enabled);
size_t bondry_test_open_count(void);
size_t bondry_test_close_count(void);
size_t bondry_test_create_client_count(void);
size_t bondry_test_set_client_enabled_count(void);
size_t bondry_test_issue_token_count(void);
size_t bondry_test_rotate_token_count(void);
size_t bondry_test_revoke_token_count(void);
size_t bondry_test_authenticate_count(void);
size_t bondry_test_recent_audit_count(void);
size_t bondry_test_principal_audit_count(void);
size_t bondry_test_issued_token_clear_count(void);
size_t bondry_test_add_grant_count(void);
size_t bondry_test_remove_grant_count(void);
size_t bondry_test_register_capability_count(void);
size_t bondry_test_unregister_capability_count(void);
size_t bondry_test_dispatch_count(void);
size_t bondry_test_release_capability_count(void);
size_t bondry_test_server_start_count(void);
size_t bondry_test_server_stop_count(void);
size_t bondry_test_server_configuration_length(void);
uint8_t bondry_test_server_configuration_byte(size_t index);
size_t bondry_test_path_length(void);
size_t bondry_test_key_length(void);
uint8_t bondry_test_key_byte(size_t index);
size_t bondry_test_identifier_length(void);
uint8_t bondry_test_identifier_byte(size_t index);
size_t bondry_test_label_length(void);
uint8_t bondry_test_label_byte(size_t index);
uint64_t bondry_test_expiration_seconds(void);
uint8_t bondry_test_has_expiration(void);
uint8_t bondry_test_enabled(void);
size_t bondry_test_adapter_length(void);
uint8_t bondry_test_adapter_byte(size_t index);
size_t bondry_test_capability_length(void);
uint8_t bondry_test_capability_byte(size_t index);
size_t bondry_test_summary_length(void);
uint8_t bondry_test_summary_byte(size_t index);
size_t bondry_test_schema_length(void);
uint8_t bondry_test_schema_byte(size_t index);
uint32_t bondry_test_capability_effect(void);
size_t bondry_test_input_length(void);
uint8_t bondry_test_input_byte(size_t index);
uint32_t bondry_test_principal_kind(void);

#endif
