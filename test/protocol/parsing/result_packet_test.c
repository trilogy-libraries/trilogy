#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static uint8_t result_packet[] = {0x01};

TEST test_parse_result_packet()
{
    trilogy_result_packet_t packet;

    int err = trilogy_parse_result_packet(result_packet, sizeof(result_packet), &packet);
    ASSERT_OK(err);

    ASSERT_EQ(1, packet.column_count);

    PASS();
}

TEST test_parse_result_packet_truncated()
{
    trilogy_result_packet_t packet;

    int err = trilogy_parse_result_packet(result_packet, sizeof(result_packet) - 1, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

int parse_result_packet_test()
{
    RUN_TEST(test_parse_result_packet);
    RUN_TEST(test_parse_result_packet_truncated);

    return 0;
}
