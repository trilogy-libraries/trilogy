#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

TEST test_build_set_option_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    const uint16_t option = 1;

    err = trilogy_build_set_option_packet(&builder, option);
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x03, 0x00, 0x00, 0x00, 0x1a, 0x01, 0x00};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int build_set_option_packet_test()
{
    RUN_TEST(test_build_set_option_packet);

    return 0;
}
