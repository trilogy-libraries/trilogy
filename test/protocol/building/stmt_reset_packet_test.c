#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

TEST test_stmt_reset_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint32_t stmt_id = 1;

    err = trilogy_build_stmt_reset_packet(&builder, stmt_id);
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x05, 0x00, 0x00, 0x00, 0x1a, 0x01, 0x00, 0x00, 0x00};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int stmt_reset_packet_test()
{
    RUN_TEST(test_stmt_reset_packet);

    return 0;
}
