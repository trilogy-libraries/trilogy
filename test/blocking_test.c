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

TEST test_blocking_set_option()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const uint16_t option = 1;

    int err = trilogy_set_option(&conn, option);
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

TEST test_blocking_stmt_prepare()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_str()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    const char str[] = {'t', 'e', 's', 't'};
    size_t len = sizeof(str);
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .type = TRILOGY_TYPE_VAR_STRING, .as.str.data = str, .as.str.len = len}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_MEM_EQ(values[0].as.str.data, "test", values[0].as.str.len);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_integer()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    uint32_t unsigned_val = 1234;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_LONG, .as.uint32 = unsigned_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.uint32, unsigned_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    int32_t signed_val = -1234;

    trilogy_binary_value_t signed_binds[] = {
        {.is_null = false, .is_unsigned = false, .type = TRILOGY_TYPE_LONG, .as.int32 = signed_val}};

    err = trilogy_stmt_execute(&conn, &stmt, flags, signed_binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.int32, signed_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_double()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    double dbl_val = 1234.5;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_DOUBLE, .as.dbl = dbl_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.dbl, dbl_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_float() {
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    float float_val = 1234.5f;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_FLOAT, .as.flt = float_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.flt, float_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_long()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    uint64_t unsigned_val = 1234;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_LONGLONG, .as.uint64 = unsigned_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.uint64, unsigned_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    int64_t signed_val = -1234;

    trilogy_binary_value_t signed_binds[] = {
        {.is_null = false, .is_unsigned = false, .type = TRILOGY_TYPE_LONGLONG, .as.int64 = signed_val}};

    err = trilogy_stmt_execute(&conn, &stmt, flags, signed_binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.int64, signed_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_short() {
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    uint16_t unsigned_val = 1234;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_SHORT, .as.uint16 = unsigned_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.uint16, unsigned_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    int16_t signed_val = -1234;

    trilogy_binary_value_t signed_binds[] = {
        {.is_null = false, .is_unsigned = false, .type = TRILOGY_TYPE_SHORT, .as.int16 = signed_val}};

    err = trilogy_stmt_execute(&conn, &stmt, flags, signed_binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.int16, signed_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_tiny() {
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;
    uint8_t unsigned_val = 123;
    trilogy_binary_value_t binds[] = {
        {.is_null = false, .is_unsigned = true, .type = TRILOGY_TYPE_TINY, .as.uint8 = unsigned_val}};

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.uint8, unsigned_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    int8_t signed_val = -123;

    trilogy_binary_value_t signed_binds[] = {
        {.is_null = false, .is_unsigned = false, .type = TRILOGY_TYPE_TINY, .as.int8 = signed_val}};

    err = trilogy_stmt_execute(&conn, &stmt, flags, signed_binds, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.int8, signed_val);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_datetime()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT CAST('2022-01-31 21:15:45' AS DATETIME)";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(0, stmt.parameter_count);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, NULL, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.date.year, 2022);
    ASSERT_EQ(values[0].as.date.month, 1);
    ASSERT_EQ(values[0].as.date.day, 31);
    ASSERT_EQ(values[0].as.date.datetime.hour, 21);
    ASSERT_EQ(values[0].as.date.datetime.minute, 15);
    ASSERT_EQ(values[0].as.date.datetime.second, 45);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_time()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT CAST('21:15:45' AS TIME)";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(0, stmt.parameter_count);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, NULL, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.time.hour, 21);
    ASSERT_EQ(values[0].as.time.minute, 15);
    ASSERT_EQ(values[0].as.time.second, 45);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_execute_year()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT CAST('2023' AS YEAR)";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(0, stmt.parameter_count);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    uint8_t flags = 0x00;

    uint64_t column_count;

    err = trilogy_stmt_execute(&conn, &stmt, flags, NULL, &column_count);
    ASSERT_OK(err);

    ASSERT_EQ(1, column_count);

    trilogy_column_packet_t columns[1];
    err = trilogy_read_full_column(&conn, &columns[0]);
    ASSERT_OK(err);

    trilogy_binary_value_t values[1];
    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_OK(err);

    ASSERT_EQ(values[0].as.year, 2023);

    err = trilogy_stmt_read_full_row(&conn, &stmt, columns, values);
    ASSERT_EOF(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_reset()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    err = trilogy_stmt_reset(&conn, &stmt);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_blocking_stmt_close()
{
    trilogy_conn_t conn;

    connect_conn(&conn);

    const char *query = "SELECT ?";
    trilogy_stmt_t stmt;

    int err = trilogy_stmt_prepare(&conn, query, strlen(query), &stmt);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.parameter_count);

    trilogy_column_packet_t param;
    err = trilogy_read_full_column(&conn, &param);
    ASSERT_OK(err);

    ASSERT_EQ(1, stmt.column_count);

    trilogy_column_packet_t column_def;
    err = trilogy_read_full_column(&conn, &column_def);
    ASSERT_OK(err);

    err = trilogy_stmt_close(&conn, &stmt);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

int blocking_test()
{
    RUN_TEST(test_blocking_connect);
    RUN_TEST(test_blocking_change_db);
    RUN_TEST(test_blocking_set_option);
    RUN_TEST(test_blocking_ping);
    RUN_TEST(test_blocking_query);
    RUN_TEST(test_blocking_query_error);
    RUN_TEST(test_blocking_query_no_rows);
    RUN_TEST(test_blocking_stmt_prepare);
    RUN_TEST(test_blocking_stmt_execute_str);
    RUN_TEST(test_blocking_stmt_execute_integer);
    RUN_TEST(test_blocking_stmt_execute_double);
    RUN_TEST(test_blocking_stmt_execute_float);
    RUN_TEST(test_blocking_stmt_execute_long);
    RUN_TEST(test_blocking_stmt_execute_short);
    RUN_TEST(test_blocking_stmt_execute_tiny);
    RUN_TEST(test_blocking_stmt_execute_datetime);
    RUN_TEST(test_blocking_stmt_execute_time);
    RUN_TEST(test_blocking_stmt_execute_year);
    RUN_TEST(test_blocking_stmt_reset);
    RUN_TEST(test_blocking_stmt_close);

    return 0;
}
