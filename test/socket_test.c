#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/client.h"
#include "trilogy/error.h"

#define do_connect(CONN)                                                                                               \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect(CONN, get_connopt());                                                                    \
        ASSERT_OK(err);                                                                                                \
    } while (0)

TEST test_check_connected()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    int err = trilogy_sock_check(conn.socket);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}


TEST test_check_disconnected()
{
    trilogy_conn_t conn;

    do_connect(&conn);
    shutdown(trilogy_sock_fd(conn.socket), SHUT_RD);

    int err = trilogy_sock_check(conn.socket);
    ASSERT_ERR(TRILOGY_CLOSED_CONNECTION, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_check_closed()
{
    trilogy_conn_t conn;

    do_connect(&conn);
    close_socket(&conn);

    int err = trilogy_sock_check(conn.socket);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int socket_test()
{
    RUN_TEST(test_check_connected);
    RUN_TEST(test_check_disconnected);
    RUN_TEST(test_check_closed);

    return 0;
}
