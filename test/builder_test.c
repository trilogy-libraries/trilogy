#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/builder.h"
#include "trilogy/error.h"
#include "trilogy/packet_parser.h"

TEST test_builder_write_uint8()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x61);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x01, 0x00, 0x00, 0x00, 0x61};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint8_split_packet()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    size_t len = TRILOGY_MAX_PACKET_LEN - 1;
    uint8_t *bytes = malloc(len);

    err = trilogy_builder_write_buffer(&builder, bytes, len);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x00);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x00);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected_header1[] = {0xFF, 0xFF, 0xFF, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected_header1, sizeof(expected_header1));

    const uint8_t expected_header2[] = {0x01, 0x00, 0x00, 0x01};
    ASSERT_MEM_EQ(builder.buffer->buff + TRILOGY_MAX_PACKET_LEN + 4, expected_header2, sizeof(expected_header2));

    free(bytes);

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint8_exceeds_small_max()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_set_max_packet_length(&builder, 2);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x01);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x02);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x03);
    ASSERT_EQ(TRILOGY_MAX_PACKET_EXCEEDED, err);

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint8_exceeds_large_max()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    size_t max = TRILOGY_MAX_PACKET_LEN * 2;
    err = trilogy_builder_set_max_packet_length(&builder, max);
    ASSERT_OK(err);

    size_t len = max - 2;
    uint8_t *bytes = malloc(len);

    err = trilogy_builder_write_buffer(&builder, bytes, len);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x01);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x02);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x03);
    ASSERT_EQ(TRILOGY_MAX_PACKET_EXCEEDED, err);

    free(bytes);

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint16()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint16(&builder, 0x61);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x02, 0x00, 0x00, 0x00, 0x61, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint32()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint32(&builder, 0x61);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x04, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_uint64()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint64(&builder, 0x61);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x08, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_lenenc8()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_lenenc(&builder, 0x01);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x01, 0x00, 0x00, 0x00, 0x01};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_lenenc16()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_lenenc(&builder, 0xff1);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x03, 0x00, 0x00, 0x00, 0xFC, 0xF1, 0x0F};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_lenenc24()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_lenenc(&builder, 0xffff1);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x04, 0x00, 0x00, 0x00, 0xFD, 0xF1, 0xFF, 0x0F};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_lenenc64()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_lenenc(&builder, 0xffffff1);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x09, 0x00, 0x00, 0x00, 0xFE, 0xF1, 0xFF, 0xFF, 0x0F, 0x00, 0x00, 0x00, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_buffer()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint8_t bytes[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    err = trilogy_builder_write_buffer(&builder, bytes, sizeof(bytes));
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x05, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_large_buffer()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    size_t len = TRILOGY_MAX_PACKET_LEN + 10;
    uint8_t *bytes = malloc(len);

    err = trilogy_builder_write_buffer(&builder, bytes, len);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected_header1[] = {0xFF, 0xFF, 0xFF, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected_header1, sizeof(expected_header1));

    const uint8_t expected_header2[] = {0x0A, 0x00, 0x00, 0x01};
    ASSERT_MEM_EQ(builder.buffer->buff + TRILOGY_MAX_PACKET_LEN + 4, expected_header2, sizeof(expected_header2));

    free(bytes);

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_lenenc_buffer()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint8_t bytes[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    err = trilogy_builder_write_lenenc_buffer(&builder, bytes, sizeof(bytes));
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x06, 0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_write_string()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    uint8_t bytes[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00};

    err = trilogy_builder_write_string(&builder, (const char *)bytes);
    ASSERT_OK(err);

    trilogy_builder_finalize(&builder);

    const uint8_t expected[] = {0x06, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00};
    ASSERT_MEM_EQ(builder.buffer->buff, expected, sizeof(expected));

    trilogy_buffer_free(&buff);
    PASS();
}

TEST test_builder_set_insufficient_max()
{
    trilogy_buffer_t buff;
    int err = trilogy_buffer_init(&buff, 1);
    ASSERT_OK(err);

    trilogy_builder_t builder;
    err = trilogy_builder_init(&builder, &buff, 0);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x01);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x02);
    ASSERT_OK(err);

    err = trilogy_builder_write_uint8(&builder, 0x03);
    ASSERT_OK(err);

    err = trilogy_builder_set_max_packet_length(&builder, 2);
    ASSERT_EQ(TRILOGY_MAX_PACKET_EXCEEDED, err);

    trilogy_buffer_free(&buff);
    PASS();
}

int builder_test()
{
    RUN_TEST(test_builder_write_uint8);
    RUN_TEST(test_builder_write_uint8_split_packet);
    RUN_TEST(test_builder_write_uint8_exceeds_small_max);
    RUN_TEST(test_builder_write_uint8_exceeds_large_max);
    RUN_TEST(test_builder_write_uint16);
    RUN_TEST(test_builder_write_uint32);
    RUN_TEST(test_builder_write_uint64);
    RUN_TEST(test_builder_write_lenenc8);
    RUN_TEST(test_builder_write_lenenc16);
    RUN_TEST(test_builder_write_lenenc24);
    RUN_TEST(test_builder_write_lenenc64);
    RUN_TEST(test_builder_write_buffer);
    RUN_TEST(test_builder_write_large_buffer);
    RUN_TEST(test_builder_write_lenenc_buffer);
    RUN_TEST(test_builder_write_string);
    RUN_TEST(test_builder_set_insufficient_max);

    return 0;
}
