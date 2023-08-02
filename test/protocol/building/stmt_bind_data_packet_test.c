#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

TEST test_stmt_bind_data_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint32_t stmt_id = 1;
    uint32_t param_id = 2;
    uint8_t data[] = {'d', 'a', 't', 'a'};
    size_t data_len = sizeof(data);

    err = trilogy_build_stmt_bind_data_packet(&builder, stmt_id, param_id, data, data_len);
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x0b, 0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 'd', 'a',
                                       't', 'a'};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int stmt_bind_data_packet_test()
{
    RUN_TEST(test_stmt_bind_data_packet);

    return 0;
}
