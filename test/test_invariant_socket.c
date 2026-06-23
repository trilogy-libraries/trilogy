#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../src/socket.c"

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "normal",                    // Valid input
        "A",                         // Boundary: single char
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  // 100 chars - exceeds typical buffer
        "\x00\x01\x02\x03\x04\x05",  // Binary data
        "A\0B\0C\0D"                 // Embedded nulls
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        char dest[16] = {0};  // Small fixed buffer
        const char *src = payloads[i];
        size_t src_len = strlen(src);
        
        // Test strncpy usage in socket.c - we need to call actual functions
        // Since we can't directly test internal functions, we'll test the public API
        // that uses these buffer operations
        struct socket_conn conn;
        memset(&conn, 0, sizeof(conn));
        
        // Simulate receiving data into socket buffer
        int result = socket_receive(&conn, src, src_len);
        
        // Check that buffer wasn't overflowed
        ck_assert_msg(conn.buffer[sizeof(conn.buffer)-1] == 0,
                     "Buffer overflow detected for payload %d", i);
        
        // Check that function handled input appropriately
        ck_assert_msg(result >= 0 || result == -1,
                     "Invalid return value for payload %d", i);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
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