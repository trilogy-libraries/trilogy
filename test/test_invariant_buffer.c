#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "../src/buffer.h"

START_TEST(test_buffer_write_never_exceeds_capacity)
{
    // Invariant: Buffer writes never exceed declared buffer capacity
    const char *payloads[] = {
        "A",                    // Valid input (1 byte)
        "ABCDEFGHIJKLMNOP",     // Boundary case (16 bytes, exact capacity)
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",  // Oversized (36 bytes, 2.25x capacity)
        "EXPLOIT"               // Exact exploit payload from report
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        buffer_t *buff = buffer_create(16);  // Fixed capacity buffer
        ck_assert_ptr_nonnull(buff);
        
        size_t payload_len = strlen(payloads[i]);
        int result = buffer_write(buff, payloads[i], payload_len);
        
        // Security property: Either write succeeds within bounds or fails safely
        if (payload_len > 16) {
            // Oversized payload must be rejected or truncated
            ck_assert(result == -1 || buff->len <= 16);
        } else {
            // Valid payload must succeed and stay within bounds
            ck_assert(result == 0);
            ck_assert(buff->len <= 16);
        }
        
        // Additional safety check: No buffer overflow in internal structure
        ck_assert(buff->len <= 16);
        
        buffer_destroy(buff);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_write_never_exceeds_capacity);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}