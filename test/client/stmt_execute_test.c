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

TEST test_stmt_execute_send()
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

    uint8_t flags = 0x00;
    const char str[] = {'t','e','s','t'};
    size_t len = sizeof(str);
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .type = TRILOGY_TYPE_VAR_STRING, .as.str.data = str, .as.str.len = len}};

    err = trilogy_stmt_execute_send(&conn, &stmt, flags, binds);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_stmt_execute_send_closed_socket()
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

    uint8_t flags = 0x00;
    const char str[] = {'t', 'e', 's', 't'};
    size_t len = sizeof(str);
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .type = TRILOGY_TYPE_VAR_STRING, .as.str.data = str, .as.str.len = len}};

    err = trilogy_stmt_execute_send(&conn, &stmt, flags, binds);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_stmt_execute_recv()
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

    uint8_t flags = 0x00;
    const char str[] = {'t', 'e', 's', 't'};
    size_t len = sizeof(str);
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .type = TRILOGY_TYPE_VAR_STRING, .as.str.data = str, .as.str.len = len}};

    err = trilogy_stmt_execute_send(&conn, &stmt, flags, binds);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    uint64_t column_count;

    err = trilogy_stmt_execute_recv(&conn, &column_count);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_stmt_execute_recv(&conn, &column_count);
    }
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];

    for (uint64_t i = 0; i < column_count; i++) {
        trilogy_column_packet_t *column = &columns[i];

        err = trilogy_read_full_column(&conn, column);

        if (err < 0) {
            return err;
        }
    }

    trilogy_binary_value_t values[1];

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_MEM_EQ(values[0].as.str.data, "test", values[0].as.str.len);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_stmt_execute_recv_closed_socket()
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

    uint8_t flags = 0x00;
    const char str[] = {'t', 'e', 's', 't'};
    size_t len = sizeof(str);
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .type = TRILOGY_TYPE_VAR_STRING, .as.str.data = str, .as.str.len = len}};

    err = trilogy_stmt_execute_send(&conn, &stmt, flags, binds);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    close_socket(&conn);

    uint64_t column_count;

    err = trilogy_stmt_execute_recv(&conn, &column_count);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_stmt_execute_test()
{
    RUN_TEST(test_stmt_execute_send);
    RUN_TEST(test_stmt_execute_send_closed_socket);
    RUN_TEST(test_stmt_execute_recv);
    RUN_TEST(test_stmt_execute_recv_closed_socket);

    return 0;
}
