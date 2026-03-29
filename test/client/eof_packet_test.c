#include <stdint.h>

#include "../test.h"

#include "trilogy/client.h"
#include "trilogy/protocol.h"

bool is_eof_packet(trilogy_conn_t *conn);

static int setup_conn_packet(trilogy_conn_t *conn, uint8_t packet_type, size_t packet_len, uint32_t capabilities)
{
    int err = trilogy_init(conn);
    if (err != TRILOGY_OK) {
        return err;
    }

    conn->packet_buffer.buff[0] = packet_type;
    conn->packet_buffer.len = packet_len;
    conn->capabilities = capabilities;

    return TRILOGY_OK;
}

TEST test_is_eof_packet_no_eof_marker()
{
    trilogy_conn_t conn;

    int err = setup_conn_packet(&conn, TRILOGY_PACKET_ERR, 1, 0);
    ASSERT_OK(err);

    ASSERT_EQ(false, is_eof_packet(&conn));

    trilogy_free(&conn);
    PASS();
}

TEST test_is_eof_packet_deprecated_eof_packet()
{
    trilogy_conn_t conn;

    int err = setup_conn_packet(&conn, TRILOGY_PACKET_EOF, 8, 0);
    ASSERT_OK(err);

    ASSERT_EQ(true, is_eof_packet(&conn));

    trilogy_free(&conn);
    PASS();
}

TEST test_is_eof_packet_data_without_deprecated_eof_support()
{
    trilogy_conn_t conn;

    int err = setup_conn_packet(&conn, TRILOGY_PACKET_EOF, 9, 0);
    ASSERT_OK(err);

    ASSERT_EQ(false, is_eof_packet(&conn));

    trilogy_free(&conn);
    PASS();
}

TEST test_is_eof_packet_max_length_ok_packet_with_eof_marker()
{
    trilogy_conn_t conn;

    int err = setup_conn_packet(&conn, TRILOGY_PACKET_EOF, TRILOGY_MAX_PACKET_LEN,
                                TRILOGY_CAPABILITIES_DEPRECATE_EOF);
    ASSERT_OK(err);

    ASSERT_EQ(true, is_eof_packet(&conn));

    trilogy_free(&conn);
    PASS();
}

TEST test_is_eof_packet_data_with_deprecated_eof_support()
{
    trilogy_conn_t conn;

    int err = setup_conn_packet(&conn, TRILOGY_PACKET_EOF, TRILOGY_MAX_PACKET_LEN + 1,
                                TRILOGY_CAPABILITIES_DEPRECATE_EOF);
    ASSERT_OK(err);

    ASSERT_EQ(false, is_eof_packet(&conn));

    trilogy_free(&conn);
    PASS();
}

int client_eof_packet_test()
{
    RUN_TEST(test_is_eof_packet_no_eof_marker);
    RUN_TEST(test_is_eof_packet_deprecated_eof_packet);
    RUN_TEST(test_is_eof_packet_data_without_deprecated_eof_support);
    RUN_TEST(test_is_eof_packet_max_length_ok_packet_with_eof_marker);
    RUN_TEST(test_is_eof_packet_data_with_deprecated_eof_support);

    return 0;
}
