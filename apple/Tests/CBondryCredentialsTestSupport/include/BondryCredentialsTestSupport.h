#ifndef BONDRY_CREDENTIALS_TEST_SUPPORT_H
#define BONDRY_CREDENTIALS_TEST_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

void bondry_credentials_test_reset(void);
void bondry_credentials_test_set_abi_version(uint32_t version);
void bondry_credentials_test_set_open_status(int32_t status);
void bondry_credentials_test_set_capabilities(
    uint32_t protection,
    uint32_t access,
    uint8_t supports_unattended_access
);
void bondry_credentials_test_grow_next_load(uint8_t appended_byte);
size_t bondry_credentials_test_open_count(void);
size_t bondry_credentials_test_close_count(void);

#endif
