#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/buffer.h"
#include "trilogy/error.h"

TEST test_buffer_expand()
{
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);
    ASSERT_EQ(0, buff.len);
    ASSERT_EQ(1, buff.cap);

    err = trilogy_buffer_expand(&buff, 1);
    ASSERT_OK(err);
    ASSERT_EQ(0, buff.len);
    ASSERT_EQ(1, buff.cap);

    err = trilogy_buffer_expand(&buff, 2);
    ASSERT_OK(err);
    ASSERT_EQ(0, buff.len);
    ASSERT_EQ(2, buff.cap);

    trilogy_buffer_free(&buff);

    PASS();
}

TEST test_buffer_putc()
{
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);
    ASSERT_EQ(0, buff.len);
    ASSERT_EQ(1, buff.cap);

    err = trilogy_buffer_putc(&buff, 'a');
    ASSERT_OK(err);
    ASSERT_EQ(1, buff.len);
    ASSERT_EQ(1, buff.cap);

    err = trilogy_buffer_putc(&buff, 'b');
    ASSERT_OK(err);
    ASSERT_EQ(2, buff.len);
    ASSERT_EQ(2, buff.cap);
    ASSERT_MEM_EQ(buff.buff, "ab", 2);

    trilogy_buffer_free(&buff);

    PASS();
}

TEST test_buffer_puts()
{
    trilogy_buffer_t buff;

    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);
    ASSERT_EQ(0, buff.len);
    ASSERT_EQ(1, buff.cap);

    err = trilogy_buffer_write(&buff, (uint8_t *)"aaaaBBBB", 4);
    ASSERT_OK(err);
    ASSERT_EQ(4, buff.len);
    ASSERT_EQ(4, buff.cap);

    err = trilogy_buffer_write(&buff, (uint8_t *)"ccccccc", 8);
    ASSERT_OK(err);
    ASSERT_EQ(12, buff.len);
    ASSERT_EQ(16, buff.cap);
    ASSERT_MEM_EQ(buff.buff, (uint8_t *)"aaaaccccccc", 12);

    trilogy_buffer_free(&buff);

    PASS();
}

int buffer_test()
{
    RUN_TEST(test_buffer_expand);
    RUN_TEST(test_buffer_putc);
    RUN_TEST(test_buffer_puts);

    return 0;
}
