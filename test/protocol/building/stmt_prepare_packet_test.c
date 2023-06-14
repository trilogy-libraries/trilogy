#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

TEST test_stmt_prepare_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    const char *sql = "SELECT ?";
    size_t sql_len = strlen(sql);

    err = trilogy_build_stmt_prepare_packet(&builder, sql, sql_len);
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x09, 0x00, 0x00, 0x00, 0x16, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '?'};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int stmt_prepare_packet_test()
{
    RUN_TEST(test_stmt_prepare_packet);

    return 0;
}
