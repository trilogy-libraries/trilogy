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
    } while (0);

TEST test_change_db_send()
{
    trilogy_conn_t conn;
    const char *default_db = get_connopt()->database;

    do_connect(&conn);

    int err = trilogy_change_db_send(&conn, default_db, strlen(default_db));
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_change_db_send_closed_socket()
{
    trilogy_conn_t conn;
    const char *default_db = get_connopt()->database;

    do_connect(&conn);

    close_socket(&conn);

    int err = trilogy_change_db_send(&conn, default_db, strlen(default_db));
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_change_db_recv()
{
    trilogy_conn_t conn;
    const char *default_db = get_connopt()->database;

    do_connect(&conn);

    int err = trilogy_change_db_send(&conn, default_db, strlen(default_db));
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    err = trilogy_change_db_recv(&conn);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);

        ASSERT_OK(err);
        err = trilogy_change_db_recv(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_change_db_recv_closed_socket()
{
    trilogy_conn_t conn;
    const char *default_db = get_connopt()->database;

    do_connect(&conn);

    int err = trilogy_change_db_send(&conn, default_db, strlen(default_db));
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_change_db_send(&conn, default_db, strlen(default_db));
    }
    ASSERT_OK(err);

    close_socket(&conn);

    err = trilogy_change_db_recv(&conn);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_change_db_test()
{
    RUN_TEST(test_change_db_send);
    RUN_TEST(test_change_db_send_closed_socket);
    RUN_TEST(test_change_db_recv);
    RUN_TEST(test_change_db_recv_closed_socket);

    return 0;
}
