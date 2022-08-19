#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/blocking.h"
#include "trilogy/error.h"

#define connect_conn(CONN)                                                                                             \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect((CONN), get_connopt());                                                                  \
        ASSERT_OK(err);                                                                                                \
    } while (0)

TEST test_blocking_connect()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    int err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_change_db()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *db = "test";

    int err = trilogy_change_db(&conn, db, strlen(db));
    ASSERT_OK(err);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_ping()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    int err = trilogy_ping(&conn);
    ASSERT_OK(err);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_query()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT 1";
    uint64_t column_count;

    int err = trilogy_query(&conn, query, strlen(query), &column_count);
    ASSERT_ERR(TRILOGY_HAVE_RESULTS, err);
    ASSERT_EQ(1, column_count);

    trilogy_column_t column;
    err = trilogy_read_full_column(&conn, &column);
    ASSERT_OK(err);

    ASSERT_MEM_EQ(column.catalog, "def", column.catalog_len);
    ASSERT_EQ(0, column.schema_len);
    ASSERT_EQ(0, column.table_len);
    ASSERT_EQ(0, column.original_table_len);
    ASSERT_MEM_EQ(column.name, "1", column.name_len);
    ASSERT_EQ(0, column.original_name_len);
    ASSERT_EQ(TRILOGY_CHARSET_BINARY, column.charset);
    ASSERT(column.len == 1 || column.len == 2);
    ASSERT(column.type == TRILOGY_TYPE_LONGLONG || column.type == TRILOGY_TYPE_LONG);
    ASSERT(column.flags & TRILOGY_COLUMN_FLAG_BINARY);
    ASSERT(column.flags & TRILOGY_COLUMN_FLAG_NOT_NULL);
    ASSERT_EQ(0, column.decimals);
    ASSERT_EQ(0, column.default_value_len);

    trilogy_value_t row;
    err = trilogy_read_full_row(&conn, &row);
    ASSERT_OK(err);
    ASSERT_MEM_EQ(row.data, "1", row.data_len);

    err = trilogy_read_full_row(&conn, &row);
    ASSERT_ERR(TRILOGY_EOF, err);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_query_error()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "BAD SYNTAX";
    uint64_t column_count;

    int err = trilogy_query(&conn, query, strlen(query), &column_count);
    ASSERT_ERR(TRILOGY_ERR, err);
    ASSERT(conn.error_message_len > 0);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_query_no_rows()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "set @myvar = 1";
    uint64_t column_count;

    int err = trilogy_query(&conn, query, strlen(query), &column_count);
    ASSERT_OK(err);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

int blocking_test()
{
    RUN_TEST(test_blocking_connect);
    RUN_TEST(test_blocking_change_db);
    RUN_TEST(test_blocking_ping);
    RUN_TEST(test_blocking_query);
    RUN_TEST(test_blocking_query_error);
    RUN_TEST(test_blocking_query_no_rows);

    return 0;
}
