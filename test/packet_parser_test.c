#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/error.h"
#include "trilogy/packet_parser.h"

const uint8_t empty_packet[] = {0x00, 0x00, 0x00, 0x00};

const uint8_t multiple_packet_buffer[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01};

const uint8_t handshake_packet[] = {0x4a, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x36, 0x2e, 0x32, 0x37, 0x00, 0xf5,
                                    0x02, 0x00, 0x00, 0x64, 0x63, 0x47, 0x75, 0x39, 0x5b, 0x40, 0x6d, 0x00, 0xff,
                                    0xf7, 0x21, 0x02, 0x00, 0x7F, 0x80, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x25, 0x6e, 0x7b, 0x3f, 0x68, 0x6d, 0x6c, 0x56, 0x49,
                                    0x4c, 0x24, 0x69, 0x00, 0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74,
                                    0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00};

static const uint8_t *expected_packet;
static size_t expected_len = 0;

static size_t packets_received;
static size_t last_packet_len;
static char last_packet[512];

static void reset_last_packet()
{
    packets_received = 0;
    last_packet_len = 0;
}

static int on_packet_begin(void *opaque)
{
    (void)opaque;

    return TRILOGY_OK;
}

static int on_packet_data(void *opaque, const uint8_t *data, size_t len)
{
    (void)opaque;
    (void)len;

    packets_received++;
    last_packet_len = len;
    memcpy(last_packet, data, len);

    return TRILOGY_OK;
}

static int on_packet_end(void *opaque)
{
    (void)opaque;

    // pause packet parsing so we can return the packet we just read to the
    // caller
    return 1;
}

static trilogy_packet_parser_callbacks_t packet_parser_callbacks = {
    .on_packet_begin = on_packet_begin,
    .on_packet_data = on_packet_data,
    .on_packet_end = on_packet_end,
};

TEST test_parse_packet()
{
    trilogy_packet_parser_t parser;
    trilogy_packet_parser_init(&parser, &packet_parser_callbacks);

    int err;

    expected_packet = handshake_packet;
    expected_len = sizeof(handshake_packet) - 4;

    reset_last_packet();

    size_t num_parsed = trilogy_packet_parser_execute(&parser, handshake_packet, sizeof(handshake_packet), &err);

    ASSERT_EQ(sizeof(handshake_packet), num_parsed);
    ASSERT_EQ(1, packets_received);
    ASSERT_EQ(expected_len, last_packet_len);
    ASSERT_MEM_EQ(expected_packet + 4, last_packet, expected_len);

    PASS();
}

TEST test_parse_partial_packet()
{
    trilogy_packet_parser_t parser;
    trilogy_packet_parser_init(&parser, &packet_parser_callbacks);

    int err;

    expected_packet = handshake_packet;
    expected_len = sizeof(handshake_packet) - 14;

    reset_last_packet();

    size_t num_parsed = trilogy_packet_parser_execute(&parser, handshake_packet, sizeof(handshake_packet) - 10, &err);

    ASSERT_EQ(sizeof(handshake_packet) - 10, num_parsed);
    ASSERT_EQ(1, packets_received);
    ASSERT_EQ(expected_len, last_packet_len);
    ASSERT_MEM_EQ(expected_packet + 4, last_packet, expected_len);

    PASS();
}

TEST test_parse_empty_packet()
{
    trilogy_packet_parser_t parser;
    trilogy_packet_parser_init(&parser, &packet_parser_callbacks);

    int err;

    expected_packet = empty_packet;
    expected_len = 0;

    reset_last_packet();

    size_t num_parsed = trilogy_packet_parser_execute(&parser, empty_packet, sizeof(empty_packet), &err);

    ASSERT_EQ(4, num_parsed);
    ASSERT_EQ(0, packets_received);

    PASS();
}

TEST test_parse_multi_packet_buffer()
{
    trilogy_packet_parser_t parser;
    trilogy_packet_parser_init(&parser, &packet_parser_callbacks);

    int err;

    expected_packet = multiple_packet_buffer;
    expected_len = 1;

    reset_last_packet();

    size_t num_parsed =
        trilogy_packet_parser_execute(&parser, multiple_packet_buffer, sizeof(multiple_packet_buffer), &err);

    ASSERT_EQ(5, num_parsed);
    ASSERT_EQ(1, packets_received);
    ASSERT_EQ(expected_len, last_packet_len);
    ASSERT_MEM_EQ(expected_packet + 4, last_packet, expected_len);

    PASS();
}

int packet_parser_test()
{
    RUN_TEST(test_parse_packet);
    RUN_TEST(test_parse_partial_packet);
    RUN_TEST(test_parse_empty_packet);
    RUN_TEST(test_parse_multi_packet_buffer);

    return 0;
}
