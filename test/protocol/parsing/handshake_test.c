#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static const uint8_t valid_handshake_packet[] = {
    0x0a, 0x35, 0x2e, 0x36, 0x2e, 0x32, 0x37, 0x00, 0xae, 0x01, 0x00, 0x00, 0x36, 0x67, 0x28, 0x30, 0x57, 0x45, 0x35,
    0x79, 0x00, 0xff, 0xf7, 0x21, 0x02, 0x00, 0x7f, 0x80, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x23, 0x40, 0x57, 0x76, 0x6a, 0x32, 0x59, 0x48, 0x3f, 0x43, 0x71, 0x2f, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c,
    0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00};

TEST test_parse_handshake()
{
    trilogy_handshake_t packet;

    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_OK(err);

    ASSERT_EQ(0x0a, packet.proto_version);

    const char expected_version[] = "5.6.27";
    ASSERT_MEM_EQ(packet.server_version, expected_version, sizeof(expected_version));

    ASSERT_EQ(430, packet.conn_id);

    const char expected_scramble[] = "6g(0WE5y#@Wvj2YH?Cq/";
    ASSERT_MEM_EQ(packet.scramble, expected_scramble, sizeof(expected_scramble));

    ASSERT_EQ(0x807FF7FF, packet.capabilities);

    ASSERT_EQ(TRILOGY_CHARSET_UTF8_GENERAL_CI, packet.server_charset);

    ASSERT_EQ(0x00000002, packet.server_status);

    const char expected_auth_plugin[] = "mysql_native_password";
    ASSERT_MEM_EQ(packet.auth_plugin, expected_auth_plugin, sizeof(expected_auth_plugin));

    PASS();
}

TEST test_parse_handshake_truncated()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;

    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet) - 10, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_parse_handshake_invalid_protocol()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;
    handshake_packet[0] = 0xff;
    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));
    handshake_packet[21] = 0x00;
    handshake_packet[22] = 0x00;
    err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_parse_handshake_no_protocol41_flag()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;

    handshake_packet[21] = 0x00;
    handshake_packet[22] = 0x00;
    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_parse_handshake_no_secure_connection_flag()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;

    handshake_packet[21] &= (~TRILOGY_CAPABILITIES_SECURE_CONNECTION) & 0xff;
    handshake_packet[22] &= ((~TRILOGY_CAPABILITIES_SECURE_CONNECTION) >> 8) & 0xff;
    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_parse_handshake_invalid_null_filler()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;

    handshake_packet[20] = 0xff;
    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_parse_handshake_ignores_reserved_filler()
{
    uint8_t handshake_packet[sizeof(valid_handshake_packet)];
    memcpy(handshake_packet, valid_handshake_packet, sizeof(valid_handshake_packet));

    trilogy_handshake_t packet;

    handshake_packet[29] = 0xff;
    int err = trilogy_parse_handshake_packet(handshake_packet, sizeof(handshake_packet), &packet);
    ASSERT_OK(err);

    PASS();
}

int parse_handshake_test()
{
    RUN_TEST(test_parse_handshake);
    RUN_TEST(test_parse_handshake_truncated);
    RUN_TEST(test_parse_handshake_invalid_protocol);
    RUN_TEST(test_parse_handshake_no_protocol41_flag);
    RUN_TEST(test_parse_handshake_no_secure_connection_flag);
    RUN_TEST(test_parse_handshake_invalid_null_filler);
    RUN_TEST(test_parse_handshake_ignores_reserved_filler);

    return 0;
}
