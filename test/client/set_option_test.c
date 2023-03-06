#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test.h"

#include "trilogy/blocking.h"
#include "trilogy/client.h"
#include "trilogy/error.h"

#define do_connect(CONN)                                                                                               \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect(CONN, get_connopt());                                                                    \
        ASSERT_OK(err);                                                                                                \
    } while (0)

TEST test_set_option_send()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    const uint16_t option = 1;

    int err = trilogy_set_option_send(&conn, option);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_set_option_send_closed_socket()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    close_socket(&conn);

    const uint16_t option = 0;

    int err = trilogy_set_option_send(&conn, option);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_set_option_recv()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    const uint16_t option = 1;

    int err = trilogy_set_option_send(&conn, option);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    err = trilogy_set_option_recv(&conn);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_set_option_recv(&conn);
    }

    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_set_option_recv_closed_socket()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    const uint16_t option = 1;

    int err = trilogy_set_option_send(&conn, option);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    close_socket(&conn);

    err = trilogy_set_option_recv(&conn);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_set_option_test()
{
    RUN_TEST(test_set_option_send);
    RUN_TEST(test_set_option_send_closed_socket);
    RUN_TEST(test_set_option_recv);
    RUN_TEST(test_set_option_recv_closed_socket);

    return 0;
}
