#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/error.h"

TEST test_trilogy_error_strings()
{
#define XX(name, code)                                                                                                 \
    const char *name##_expected_str = #name;                                                                           \
    const char *name##_ret = trilogy_error(name);                                                                      \
    ASSERT_STRN_EQ(name##_ret, name##_expected_str, strlen(name##_expected_str));

    TRILOGY_ERROR_CODES(XX)
#undef XX

    PASS();
}

TEST test_null_for_undefined_errors()
{
    ASSERT_EQ(NULL, trilogy_error(1));

    PASS();
}

int error_test()
{
    RUN_TEST(test_trilogy_error_strings);
    RUN_TEST(test_null_for_undefined_errors);

    return 0;
}
