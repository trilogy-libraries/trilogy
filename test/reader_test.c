#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

#include "trilogy/error.h"
#include "trilogy/reader.h"

TEST test_read_uint8()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01};
    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint8_t val;

    int err = trilogy_reader_get_uint8(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_uint8_truncated()
{
    trilogy_reader_t reader;
    const uint8_t *buff = NULL;

    trilogy_reader_init(&reader, buff, 0);

    uint8_t val;

    int err = trilogy_reader_get_uint8(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_uint16()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint16_t val;

    int err = trilogy_reader_get_uint16(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_uint16_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint16_t val;

    int err = trilogy_reader_get_uint16(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_uint24()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint32_t val;

    int err = trilogy_reader_get_uint24(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_uint24_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint32_t val;

    int err = trilogy_reader_get_uint24(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_uint32()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint32_t val;

    int err = trilogy_reader_get_uint32(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_uint32_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint32_t val;

    int err = trilogy_reader_get_uint32(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_uint64()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint64_t val;

    int err = trilogy_reader_get_uint64(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_uint64_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint64_t val;

    int err = trilogy_reader_get_uint64(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_lenenc()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0xfb, 0xfc, 0x01, 0x00, 0xfd, 0x01, 0x00, 0x00,
                            0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint64_t val;

    int err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_ERR(TRILOGY_NULL_VALUE, err);

    err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_OK(err);
    ASSERT_EQ(1, val);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_lenenc_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint64_t val;

    int err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_lenenc_invalid()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0xff};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint64_t val;

    int err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_read_lenenc_empty()
{
    trilogy_reader_t reader;
    const uint8_t *buff = NULL;

    trilogy_reader_init(&reader, buff, 0);

    uint64_t val;

    int err = trilogy_reader_get_lenenc(&reader, &val);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_buffer()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;

    int err = trilogy_reader_get_buffer(&reader, sizeof(buff), (const void **)&data);
    ASSERT_OK(err);
    ASSERT_MEM_EQ(buff, data, sizeof(buff));

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_buffer_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;

    int err = trilogy_reader_get_buffer(&reader, 50, (const void **)&data);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_copy_buffer()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char data[5];

    int err = trilogy_reader_copy_buffer(&reader, sizeof(buff), (void *)data);
    ASSERT_OK(err);
    ASSERT_MEM_EQ(buff, data, sizeof(buff));

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_copy_buffer_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char data[sizeof(buff)];

    int err = trilogy_reader_copy_buffer(&reader, 50, (void *)data);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_lenenc_buffer()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01, 0x61};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint8_t *data;
    size_t len;

    int err = trilogy_reader_get_lenenc_buffer(&reader, &len, (const void **)&data);
    ASSERT_OK(err);
    ASSERT_EQ(0x01, len);
    ASSERT_EQ(0x61, data[0]);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_lenenc_buffer_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x01};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint8_t *data;
    size_t len;

    int err = trilogy_reader_get_lenenc_buffer(&reader, &len, (const void **)&data);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_lenenc_buffer_invalid()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0xff};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    uint8_t *data;
    size_t len;

    int err = trilogy_reader_get_lenenc_buffer(&reader, &len, (const void **)&data);
    ASSERT_ERR(TRILOGY_PROTOCOL_VIOLATION, err);

    PASS();
}

TEST test_read_string()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;
    size_t len;

    int err = trilogy_reader_get_string(&reader, &data, &len);
    ASSERT_OK(err);
    ASSERT_EQ(sizeof(buff) - 1, len);
    ASSERT_MEM_EQ(buff, data, len);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_read_string_truncated()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;
    size_t len;

    int err = trilogy_reader_get_string(&reader, &data, &len);
    ASSERT_ERR(TRILOGY_TRUNCATED_PACKET, err);

    PASS();
}

TEST test_read_eof_buffer()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;
    size_t len;

    int err = trilogy_reader_get_eof_buffer(&reader, &len, (const void **)&data);
    ASSERT_OK(err);
    ASSERT_EQ(sizeof(buff), len);
    ASSERT_MEM_EQ(buff, data, len);

    err = trilogy_reader_finish(&reader);
    ASSERT_OK(err);

    PASS();
}

TEST test_reader_extra_data()
{
    trilogy_reader_t reader;
    const uint8_t buff[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f};

    trilogy_reader_init(&reader, buff, sizeof(buff));

    const char *data;

    int err = trilogy_reader_get_buffer(&reader, sizeof(buff) - 2, (const void **)&data);
    ASSERT_OK(err);
    ASSERT_MEM_EQ(buff, data, sizeof(buff) - 2);

    err = trilogy_reader_finish(&reader);
    ASSERT_ERR(TRILOGY_EXTRA_DATA_IN_PACKET, err);

    PASS();
}

TEST test_reader_eof()
{
    trilogy_reader_t reader;
    trilogy_reader_init(&reader, NULL, 0);

    bool at_eof = trilogy_reader_eof(&reader);
    ASSERT(at_eof);

    PASS();
}

int reader_test()
{
    RUN_TEST(test_read_uint8);
    RUN_TEST(test_read_uint8_truncated);

    RUN_TEST(test_read_uint16);
    RUN_TEST(test_read_uint16_truncated);

    RUN_TEST(test_read_uint24);
    RUN_TEST(test_read_uint24_truncated);

    RUN_TEST(test_read_uint32);
    RUN_TEST(test_read_uint32_truncated);

    RUN_TEST(test_read_uint64);
    RUN_TEST(test_read_uint64_truncated);

    RUN_TEST(test_read_lenenc);
    RUN_TEST(test_read_lenenc_truncated);
    RUN_TEST(test_read_lenenc_invalid);
    RUN_TEST(test_read_lenenc_empty);

    RUN_TEST(test_read_buffer);
    RUN_TEST(test_read_buffer_truncated);

    RUN_TEST(test_copy_buffer);
    RUN_TEST(test_copy_buffer_truncated);

    RUN_TEST(test_read_lenenc_buffer);
    RUN_TEST(test_read_lenenc_buffer_truncated);
    RUN_TEST(test_read_lenenc_buffer_invalid);

    RUN_TEST(test_read_string);
    RUN_TEST(test_read_string_truncated);

    RUN_TEST(test_read_eof_buffer);

    RUN_TEST(test_reader_extra_data);

    RUN_TEST(test_reader_eof);

    return 0;
}
