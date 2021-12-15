#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test.h"

#include "trilogy/blocking.h"
#include "trilogy/client.h"
#include "trilogy/error.h"

TEST test_connect_send()
{
    trilogy_conn_t conn;

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    err = trilogy_connect_send(&conn, get_connopt());
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_connect_recv()
{
    trilogy_conn_t conn;

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    err = trilogy_connect_send(&conn, get_connopt());
    ASSERT_OK(err);

    trilogy_handshake_t handshake;

    err = trilogy_connect_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_connect_recv(&conn, &handshake);
    }

    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_connect_recv_after_close()
{
    trilogy_conn_t conn;

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    err = trilogy_connect_send(&conn, get_connopt());
    ASSERT_OK(err);

    close_socket(&conn);

    trilogy_handshake_t handshake;

    err = trilogy_connect_recv(&conn, &handshake);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_connect_test()
{
    RUN_TEST(test_connect_send);
    RUN_TEST(test_connect_recv);
    RUN_TEST(test_connect_recv_after_close);

    return 0;
}
