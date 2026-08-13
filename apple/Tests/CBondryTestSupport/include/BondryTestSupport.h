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

#endif
