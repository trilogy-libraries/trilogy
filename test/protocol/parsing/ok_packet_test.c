#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static uint8_t ok_packet[] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};

TEST test_parse_ok_packet()
{
    trilogy_ok_packet_t packet;

    uint32_t flags = TRILOGY_CAPABILITIES_PROTOCOL_41;

    int err = trilogy_parse_ok_packet(ok_packet, sizeof(ok_packet), flags, &packet);
    ASSERT_OK(err);

    ASSERT_EQ(0, packet.affected_rows);
    ASSERT_EQ(0, packet.last_insert_id);
    ASSERT_EQ(0x02, packet.status_flags);
    ASSERT_EQ(0, packet.warning_count);

    PASS();
}

TEST test_parse_ok_packet_truncated()
{
    trilogy_ok_packet_t packet;

    uint32_t flags = TRILOGY_CAPABILITIES_PROTOCOL_41;

    int err = trilogy_parse_ok_packet(ok_packet, sizeof(ok_packet) - 2, flags, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

int parse_ok_packet_test()
{
    RUN_TEST(test_parse_ok_packet);
    RUN_TEST(test_parse_ok_packet_truncated);

    return 0;
}
