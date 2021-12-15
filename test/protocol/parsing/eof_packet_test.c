#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static uint8_t eof_packet[] = {0xfe, 0x00, 0x00, 0x02, 0x00};

TEST test_parse_eof_packet()
{
    trilogy_eof_packet_t packet;

    uint32_t flags = TRILOGY_CAPABILITIES_PROTOCOL_41;

    int err = trilogy_parse_eof_packet(eof_packet, sizeof(eof_packet), flags, &packet);
    ASSERT_OK(err);

    ASSERT_EQ(0, packet.warning_count);
    ASSERT_EQ(0x02, packet.status_flags);

    PASS();
}

TEST test_parse_eof_packet_truncated()
{
    trilogy_eof_packet_t packet;

    uint32_t flags = TRILOGY_CAPABILITIES_PROTOCOL_41;

    int err = trilogy_parse_eof_packet(eof_packet, sizeof(eof_packet) - 3, flags, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

int parse_eof_packet_test()
{
    RUN_TEST(test_parse_eof_packet);
    RUN_TEST(test_parse_eof_packet_truncated);

    return 0;
}
