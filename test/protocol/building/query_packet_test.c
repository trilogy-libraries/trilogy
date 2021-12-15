#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static const char query[] = "SELECT * FROM users";

TEST test_build_query_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_build_query_packet(&builder, query, strlen(query));
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x14, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x4c, 0x45, 0x43, 0x54, 0x20,
                                       0x2a, 0x20, 0x46, 0x52, 0x4f, 0x4d, 0x20, 0x75, 0x73, 0x65, 0x72, 0x73};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int build_query_packet_test()
{
    RUN_TEST(test_build_query_packet);

    return 0;
}
