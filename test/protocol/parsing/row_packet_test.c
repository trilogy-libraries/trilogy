#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static uint8_t row_packet[] = {0x08, 0x48, 0x6f, 0x6d, 0x65, 0x62, 0x72, 0x65, 0x77};

static uint8_t row_packet_with_null[] = {0xfb};

TEST test_parse_row_packet()
{
    trilogy_value_t packet;

    uint64_t column_count = 1;

    int err = trilogy_parse_row_packet(row_packet, sizeof(row_packet), column_count, &packet);
    ASSERT_OK(err);
    ASSERT_EQ(false, packet.is_null);
    ASSERT_MEM_EQ(packet.data, "Homebrew", packet.data_len);

    PASS();
}

TEST test_parse_row_packet_truncated()
{
    trilogy_value_t packet;

    uint64_t column_count = 1;

    int err = trilogy_parse_row_packet(row_packet, sizeof(row_packet) - 3, column_count, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_parse_row_packet_with_null()
{
    trilogy_value_t packet;

    uint64_t column_count = 1;

    int err = trilogy_parse_row_packet(row_packet_with_null, sizeof(row_packet_with_null), column_count, &packet);
    ASSERT_OK(err);
    ASSERT_EQ(true, packet.is_null);
    ASSERT_EQ(0, packet.data_len);

    PASS();
}

int parse_row_packet_test()
{
    RUN_TEST(test_parse_row_packet);
    RUN_TEST(test_parse_row_packet_truncated);
    RUN_TEST(test_parse_row_packet_with_null);

    return 0;
}
