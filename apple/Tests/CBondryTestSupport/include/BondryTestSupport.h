#ifndef BONDRY_TEST_SUPPORT_H
#define BONDRY_TEST_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

void bondry_test_reset(void);
void bondry_test_set_abi_version(uint32_t version);
void bondry_test_set_open_status(int32_t status);
void bondry_test_set_check_status(int32_t status);
void bondry_test_set_null_handle(int enabled);
size_t bondry_test_open_count(void);
size_t bondry_test_close_count(void);
size_t bondry_test_path_length(void);
size_t bondry_test_key_length(void);
uint8_t bondry_test_key_byte(size_t index);

#endif
