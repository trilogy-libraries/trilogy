#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../test.h"

#include "trilogy/error.h"
#include "trilogy/protocol.h"

static const char db[] = "test";

TEST test_build_change_db_packet()
{
    trilogy_builder_t builder;
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_build_change_db_packet(&builder, db, strlen(db));
    ASSERT_OK(err);

    static const uint8_t expected[] = {0x05, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x73, 0x74};

    ASSERT_MEM_EQ(buff.buff, expected, buff.len);

    trilogy_buffer_free(&buff);
    PASS();
}

int build_change_db_packet_test()
{
    RUN_TEST(test_build_change_db_packet);

    return 0;
}
