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

TEST test_stmt_close_send()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    const char *sql = "SELECT ?";
    size_t sql_len = strlen(sql);

    int err = trilogy_stmt_prepare_send(&conn, sql, sql_len);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_stmt_t stmt;

    err = trilogy_stmt_prepare_recv(&conn, &stmt);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_stmt_prepare_recv(&conn, &stmt);
    }
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t params[1];

    for (uint64_t i = 0; i < stmt.parameter_count; i++) {
        trilogy_column_packet_t *param = &params[i];

        err = trilogy_read_full_column(&conn, param);

        if (err < 0) {
            return err;
        }
    }

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_defs[1];

    for (uint64_t i = 0; i < stmt.column_count; i++) {
        trilogy_column_packet_t *column = &column_defs[i];

        err = trilogy_read_full_column(&conn, column);

        if (err < 0) {
            return err;
        }
    }

    err = trilogy_stmt_close_send(&conn, &stmt);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_stmt_close_send_closed_socket()
{
    trilogy_conn_t conn;

    do_connect(&conn);

    const char *sql = "SELECT ?";
    size_t sql_len = strlen(sql);

    int err = trilogy_stmt_prepare_send(&conn, sql, sql_len);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_stmt_t stmt;

    err = trilogy_stmt_prepare_recv(&conn, &stmt);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_stmt_prepare_recv(&conn, &stmt);
    }
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t params[1];

    for (uint64_t i = 0; i < stmt.parameter_count; i++) {
        trilogy_column_packet_t *param = &params[i];

        err = trilogy_read_full_column(&conn, param);

        if (err < 0) {
            return err;
        }
    }

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_defs[1];

    for (uint64_t i = 0; i < stmt.column_count; i++) {
        trilogy_column_packet_t *column = &column_defs[i];

        err = trilogy_read_full_column(&conn, column);

        if (err < 0) {
            return err;
        }
    }

    close_socket(&conn);

    err = trilogy_stmt_close_send(&conn, &stmt);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_stmt_close_test()
{
    RUN_TEST(test_stmt_close_send);
    RUN_TEST(test_stmt_close_send_closed_socket);

    return 0;
}
