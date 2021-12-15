#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static uint8_t column_packet[] = {0x03, 0x64, 0x65, 0x66, 0x00, 0x00, 0x00, 0x11, 0x40, 0x40, 0x76, 0x65, 0x72,
                                  0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x00,
                                  0x0c, 0x21, 0x00, 0x18, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x1f, 0x00, 0x00};

TEST test_parse_column_packet()
{
    trilogy_column_packet_t packet;

    bool from_field_list = false;

    int err = trilogy_parse_column_packet(column_packet, sizeof(column_packet), from_field_list, &packet);
    ASSERT_OK(err);
    ASSERT_MEM_EQ(packet.catalog, "def", packet.catalog_len);
    ASSERT_EQ(0, packet.schema_len);
    ASSERT_EQ(0, packet.table_len);
    ASSERT_EQ(0, packet.original_table_len);
    ASSERT_MEM_EQ(packet.name, "@@version_comment", packet.name_len);
    ASSERT_EQ(0, packet.original_name_len);
    ASSERT_EQ(TRILOGY_CHARSET_UTF8_GENERAL_CI, packet.charset);
    ASSERT_EQ(24, packet.len);
    ASSERT_EQ(TRILOGY_TYPE_VAR_STRING, packet.type);
    ASSERT_EQ(0x0, packet.flags);
    ASSERT_EQ(31, packet.decimals);
    ASSERT_EQ(0, packet.default_value_len);

    PASS();
}

TEST test_parse_column_packet_truncated()
{
    trilogy_column_packet_t packet;

    bool from_field_list = false;

    int err = trilogy_parse_column_packet(column_packet, sizeof(column_packet) - 10, from_field_list, &packet);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

int parse_column_packet_test()
{
    RUN_TEST(test_parse_column_packet);
    RUN_TEST(test_parse_column_packet_truncated);

    return 0;
}
