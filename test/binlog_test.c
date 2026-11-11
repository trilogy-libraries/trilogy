#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/client.h"
#include "trilogy/error.h"

#define connect_conn(CONN)                                                                                             \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect((CONN), get_connopt());                                                                  \
        ASSERT_OK(err);                                                                                                \
    } while (0)


TEST test_binlog()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    int err = trilogy_binlog_dump(&conn, "mock", 4);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
    
}

int binlog_test()
{
    RUN_TEST(test_binlog);

    return 0;
}
