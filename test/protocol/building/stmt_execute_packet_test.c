#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

TEST test_stmt_execute_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint32_t stmt_id = 1;
    uint8_t flags = 1;
    trilogy_binary_value_t binds[] = {{.is_null = false, .type = TRILOGY_TYPE_LONG, .as.uint32 = 15}};
    uint16_t num_binds = 1;

    err = trilogy_build_stmt_execute_packet(&builder, stmt_id, flags, binds, num_binds);
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x12, 0x00, 0x00, 0x00, 0x17, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
                                       0x00, 0x00, 0x01, 0x03, 0x00, 0x0f, 0x00, 0x00, 0x00};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int stmt_execute_packet_test()
{
    RUN_TEST(test_stmt_execute_packet);

    return 0;
}
