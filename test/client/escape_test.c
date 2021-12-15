#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test.h"

#include "trilogy/client.h"
#include "trilogy/error.h"

TEST test_escape()
{
    trilogy_conn_t conn;

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    const char *escaped;
    size_t escaped_len;
    const char escape_me[] = "\"\0\'\\\n\r\x1Ahello";
    err = trilogy_escape(&conn, escape_me, sizeof(escape_me) - 1, &escaped, &escaped_len);
    ASSERT_OK(err);
    ASSERT_MEM_EQ("\\\"\\0\\'\\\\\\n\\r\\Zhello", escaped, escaped_len);

    trilogy_free(&conn);
    PASS();
}

TEST test_escape_no_backslashes()
{
    trilogy_conn_t conn;

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    uint16_t old_server_status = conn.server_status;
    conn.server_status = TRILOGY_SERVER_STATUS_NO_BACKSLASH_ESCAPES;

    const char *escaped;
    size_t escaped_len;
    const char escape_me[] = "hello ' world";
    err = trilogy_escape(&conn, escape_me, sizeof(escape_me) - 1, &escaped, &escaped_len);
    ASSERT_OK(err);
    ASSERT_MEM_EQ("hello '' world", escaped, escaped_len);

    conn.server_status = old_server_status;

    trilogy_free(&conn);
    PASS();
}

int client_escape_test()
{
    RUN_TEST(test_escape);
    RUN_TEST(test_escape_no_backslashes);

    return 0;
}
