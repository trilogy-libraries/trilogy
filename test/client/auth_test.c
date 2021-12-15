#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test.h"

#include "trilogy/blocking.h"
#include "trilogy/client.h"
#include "trilogy/error.h"

#define do_connect(CONN, HANDSHAKE)                                                                                    \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect_send(CONN, get_connopt());                                                               \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect_recv(CONN, HANDSHAKE);                                                                   \
        while (err == TRILOGY_AGAIN) {                                                                                 \
            err = wait_readable(CONN);                                                                                 \
            ASSERT_OK(err);                                                                                            \
            err = trilogy_connect_recv(CONN, HANDSHAKE);                                                               \
        }                                                                                                              \
        ASSERT_OK(err);                                                                                                \
    } while (0);

TEST test_auth_send()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_send_closed_socket()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);
    close_socket(&conn);

    int err = trilogy_auth_send(&conn, &handshake);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_recv()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    err = trilogy_auth_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_auth_recv(&conn, &handshake);
    }
    if (err == TRILOGY_AUTH_SWITCH) {
        err = trilogy_auth_switch_send(&conn, &handshake);

        while (err == TRILOGY_AGAIN) {
            err = wait_readable(&conn);
            ASSERT_OK(err);

            err = trilogy_auth_recv(&conn, &handshake);
        }
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_recv_closed_socket()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    close_socket(&conn);

    err = trilogy_auth_recv(&conn, &handshake);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_ssl_handshake()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    if (getenv("MYSQL_SSL") == NULL)
        SKIP();

    do_connect(&conn, &handshake);
    int err = trilogy_ssl_request_send(&conn);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);
        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);
    err = trilogy_sock_upgrade_ssl(conn.socket);
    ASSERT_OK(err);
    err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);
        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);
    err = trilogy_auth_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);
        err = trilogy_auth_recv(&conn, &handshake);
    }
    if (err == TRILOGY_AUTH_SWITCH) {
        err = trilogy_auth_switch_send(&conn, &handshake);

        while (err == TRILOGY_AGAIN) {
            err = wait_readable(&conn);
            ASSERT_OK(err);

            err = trilogy_auth_recv(&conn, &handshake);
        }
    }
    ASSERT_OK(err);
    trilogy_free(&conn);
    PASS();
}

int client_auth_test()
{
    RUN_TEST(test_auth_send);
    RUN_TEST(test_auth_send_closed_socket);
    RUN_TEST(test_auth_recv);
    RUN_TEST(test_auth_recv_closed_socket);
    RUN_TEST(test_ssl_handshake);

    return 0;
}
