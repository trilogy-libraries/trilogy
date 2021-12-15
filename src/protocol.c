#include <openssl/evp.h>

#include "trilogy/builder.h"
#include "trilogy/error.h"
#include "trilogy/packet_parser.h"
#include "trilogy/protocol.h"
#include "trilogy/reader.h"

#define TRILOGY_CMD_QUIT 0x01
#define TRILOGY_CMD_CHANGE_DB 0x02
#define TRILOGY_CMD_QUERY 0x03
#define TRILOGY_CMD_PING 0x0e

#define SCRAMBLE_LEN 20

static size_t min(size_t a, size_t b)
{
    if (a < b) {
        return a;
    } else {
        return b;
    }
}

#define CHECKED(expr)                                                                                                  \
    if ((rc = (expr)) < 0) {                                                                                           \
        goto fail;                                                                                                     \
    }

int trilogy_parse_ok_packet(const uint8_t *buff, size_t len, uint32_t capabilities, trilogy_ok_packet_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    // skip packet type
    CHECKED(trilogy_reader_get_uint8(&reader, NULL));

    CHECKED(trilogy_reader_get_lenenc(&reader, &out_packet->affected_rows));

    CHECKED(trilogy_reader_get_lenenc(&reader, &out_packet->last_insert_id));

    out_packet->status_flags = 0;
    out_packet->warning_count = 0;
    out_packet->txn_status_flags = 0;
    out_packet->session_status = NULL;
    out_packet->session_status_len = 0;
    out_packet->session_state_changes = NULL;
    out_packet->session_state_changes_len = 0;
    out_packet->info = NULL;
    out_packet->info_len = 0;
    out_packet->last_gtid_len = 0;

    if (capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41) {
        CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->status_flags));
        CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->warning_count));
    } else if (capabilities & TRILOGY_CAPABILITIES_TRANSACTIONS) {
        CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->txn_status_flags));
    }

    if (capabilities & TRILOGY_CAPABILITIES_SESSION_TRACK && !trilogy_reader_eof(&reader)) {
        CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->session_status_len,
                                                 (const void **)&out_packet->session_status));

        if (out_packet->status_flags & TRILOGY_SERVER_STATUS_SESSION_STATE_CHANGED) {
            CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->session_state_changes_len,
                                                     (const void **)&out_packet->session_state_changes));

            TRILOGY_SESSION_TRACK_TYPE_t type = 0;
            const char *state_info = NULL;
            size_t state_info_len = 0;

            trilogy_reader_t state_reader = TRILOGY_READER((const uint8_t *)out_packet->session_state_changes,
                                                           out_packet->session_state_changes_len);

            while (!trilogy_reader_eof(&state_reader)) {
                CHECKED(trilogy_reader_get_uint8(&state_reader, (uint8_t *)&type));
                CHECKED(trilogy_reader_get_lenenc_buffer(&state_reader, &state_info_len, (const void **)&state_info));

                switch (type) {
                case TRILOGY_SESSION_TRACK_GTIDS: {
                    trilogy_reader_t gtid_reader = TRILOGY_READER((const uint8_t *)state_info, state_info_len);
                    // There's a type with value TRILOGY_SESSION_TRACK_GTIDS tag
                    // at the beginning here we can ignore since we already had
                    // the type one level higher as well.
                    CHECKED(trilogy_reader_get_uint8(&gtid_reader, NULL));
                    CHECKED(trilogy_reader_get_lenenc_buffer(&gtid_reader, &out_packet->last_gtid_len,
                                                             (const void **)&out_packet->last_gtid));
                    if (out_packet->last_gtid_len > TRILOGY_MAX_LAST_GTID_LEN) {
                        return TRILOGY_PROTOCOL_VIOLATION;
                    }
                    break;
                }
                default:
                    break;
                }
            }
        }
    } else {
        CHECKED(trilogy_reader_get_eof_buffer(&reader, &out_packet->info_len, (const void **)&out_packet->info));
    }

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_eof_packet(const uint8_t *buff, size_t len, uint32_t capabilities, trilogy_eof_packet_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    // skip packet type
    CHECKED(trilogy_reader_get_uint8(&reader, NULL));

    if (capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41) {
        CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->warning_count));
        CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->status_flags));
    } else {
        out_packet->status_flags = 0;
        out_packet->warning_count = 0;
    }

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_err_packet(const uint8_t *buff, size_t len, uint32_t capabilities, trilogy_err_packet_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    // skip packet type
    CHECKED(trilogy_reader_get_uint8(&reader, NULL));

    CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->error_code));

    if (capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41) {
        CHECKED(trilogy_reader_get_uint8(&reader, out_packet->sql_state_marker));
        CHECKED(trilogy_reader_copy_buffer(&reader, 5, out_packet->sql_state));
    } else {
        memset(out_packet->sql_state_marker, 0, sizeof out_packet->sql_state_marker);
        memset(out_packet->sql_state, 0, sizeof out_packet->sql_state);
    }

    CHECKED(trilogy_reader_get_eof_buffer(&reader, &out_packet->error_message_len,
                                          (const void **)&out_packet->error_message));

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_auth_switch_request_packet(const uint8_t *buff, size_t len, uint32_t capabilities,
                                             trilogy_auth_switch_request_packet_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    // skip packet type
    CHECKED(trilogy_reader_get_uint8(&reader, NULL));

    if (capabilities & TRILOGY_CAPABILITIES_PLUGIN_AUTH) {
        const char *auth_plugin;
        size_t auth_plugin_len;

        CHECKED(trilogy_reader_get_string(&reader, &auth_plugin, &auth_plugin_len));
        if (auth_plugin_len > sizeof(out_packet->auth_plugin) - 1) {
            return TRILOGY_AUTH_PLUGIN_TOO_LONG;
        }
        memcpy(out_packet->auth_plugin, auth_plugin, auth_plugin_len + 1);

        const char *auth_data;
        size_t auth_data_len;
        CHECKED(trilogy_reader_get_eof_buffer(&reader, &auth_data_len, (const void **)&auth_data));
        if (auth_data_len > 21) {
            auth_data_len = 21;
        }
        memcpy(out_packet->scramble, auth_data, auth_data_len);
    } else {
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_handshake_packet(const uint8_t *buff, size_t len, trilogy_handshake_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    CHECKED(trilogy_reader_get_uint8(&reader, &out_packet->proto_version));
    if (out_packet->proto_version != 0xa) {
        // incompatible protocol version
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    const char *server_version;
    size_t server_version_len;

    CHECKED(trilogy_reader_get_string(&reader, &server_version, &server_version_len));
    server_version_len = min(server_version_len, sizeof(out_packet->server_version) - 1);
    memcpy(out_packet->server_version, server_version, server_version_len);
    out_packet->server_version[server_version_len] = '\0';

    CHECKED(trilogy_reader_get_uint32(&reader, &out_packet->conn_id));

    CHECKED(trilogy_reader_copy_buffer(&reader, 8, out_packet->scramble));

    // this should be a NULL filler
    uint8_t filler = 0;
    CHECKED(trilogy_reader_get_uint8(&reader, &filler));
    if (filler != '\0') {
        // corrupt handshake packet
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    // lower two bytes of capabilities flags
    uint16_t caps_part = 0;
    CHECKED(trilogy_reader_get_uint16(&reader, &caps_part));
    out_packet->capabilities = caps_part;

    if (!(out_packet->capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41)) {
        // incompatible protocol version
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    uint8_t server_charset;
    CHECKED(trilogy_reader_get_uint8(&reader, &server_charset));

    out_packet->server_charset = server_charset;

    CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->server_status));

    // upper 16 bits of capabilities flags

    CHECKED(trilogy_reader_get_uint16(&reader, &caps_part));
    out_packet->capabilities |= ((uint32_t)caps_part << 16);

    uint8_t auth_data_len = 0;
    CHECKED(trilogy_reader_get_uint8(&reader, &auth_data_len));
    if (!(out_packet->capabilities & TRILOGY_CAPABILITIES_PLUGIN_AUTH)) {
        // this should be a NULL filler
        if (auth_data_len != '\0') {
            // corrupt handshake packet
            return TRILOGY_PROTOCOL_VIOLATION;
        }
    }

    // This space is reserved. It should be all NULL bytes but some tools or
    // future versions of MySQL-compatible clients may use it. This library
    // opts to skip the validation as some servers don't respect the protocol.
    //
    static const uint8_t null_filler[10] = {0};

    const void *str;
    CHECKED(trilogy_reader_get_buffer(&reader, 10, &str));

    if (memcmp(str, null_filler, 10) != 0) {
        // corrupt handshake packet
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    if (out_packet->capabilities & TRILOGY_CAPABILITIES_SECURE_CONNECTION && auth_data_len > 8) {
        uint8_t remaining_auth_data_len = auth_data_len - 8;

        if (remaining_auth_data_len > 13) {
            remaining_auth_data_len = 13;
        }

        CHECKED(trilogy_reader_copy_buffer(&reader, remaining_auth_data_len, out_packet->scramble + 8));
    } else {
        // only support 4.1 protocol or newer with secure connection
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    if (out_packet->capabilities & TRILOGY_CAPABILITIES_PLUGIN_AUTH) {
        const char *auth_plugin;
        size_t auth_plugin_len;

        CHECKED(trilogy_reader_get_string(&reader, &auth_plugin, &auth_plugin_len));
        if (auth_plugin_len > sizeof(out_packet->auth_plugin) - 1) {
            return TRILOGY_AUTH_PLUGIN_TOO_LONG;
        }

        memcpy(out_packet->auth_plugin, auth_plugin, auth_plugin_len + 1);
    }

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_result_packet(const uint8_t *buff, size_t len, trilogy_result_packet_t *out_packet)
{
    int rc = 0;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    CHECKED(trilogy_reader_get_lenenc(&reader, &out_packet->column_count));

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

int trilogy_parse_row_packet(const uint8_t *buff, size_t len, uint64_t column_count, trilogy_value_t *out_values)
{
    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    for (uint64_t i = 0; i < column_count; i++) {
        void *data = NULL;
        size_t data_len = 0;

        int rc = trilogy_reader_get_lenenc_buffer(&reader, &data_len, (const void **)&data);

        switch (rc) {
        case TRILOGY_OK:
            out_values[i].is_null = false;
            out_values[i].data = data;
            out_values[i].data_len = data_len;
            break;

        case TRILOGY_NULL_VALUE:
            out_values[i].is_null = true;
            out_values[i].data_len = 0;
            break;

        default:
            return rc;
        }
    }

    return trilogy_reader_finish(&reader);
}

int trilogy_parse_column_packet(const uint8_t *buff, size_t len, bool field_list, trilogy_column_packet_t *out_packet)
{
    int rc;

    trilogy_reader_t reader = TRILOGY_READER(buff, len);

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->catalog_len, (const void **)&out_packet->catalog));

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->schema_len, (const void **)&out_packet->schema));

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->table_len, (const void **)&out_packet->table));

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->original_table_len,
                                             (const void **)&out_packet->original_table));

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->name_len, (const void **)&out_packet->name));

    CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->original_name_len,
                                             (const void **)&out_packet->original_name));

    // skip length of fixed length field until we have something to use it for
    CHECKED(trilogy_reader_get_lenenc(&reader, NULL));

    uint16_t charset;
    CHECKED(trilogy_reader_get_uint16(&reader, &charset));

    out_packet->charset = charset;

    CHECKED(trilogy_reader_get_uint32(&reader, &out_packet->len));

    uint8_t type;
    CHECKED(trilogy_reader_get_uint8(&reader, &type));
    out_packet->type = type;

    CHECKED(trilogy_reader_get_uint16(&reader, &out_packet->flags));

    CHECKED(trilogy_reader_get_uint8(&reader, &out_packet->decimals));

    // skip NULL filler
    CHECKED(trilogy_reader_get_uint16(&reader, NULL));

    out_packet->default_value_len = 0;

    if (field_list) {
        CHECKED(trilogy_reader_get_lenenc_buffer(&reader, &out_packet->default_value_len,
                                                 (const void **)&out_packet->default_value));
    }

    return trilogy_reader_finish(&reader);

fail:
    return rc;
}

static void trilogy_pack_scramble_native_hash(const char *scramble, const char *password, size_t password_len,
                                              uint8_t *buffer, unsigned int *buffer_len)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *alg;
    unsigned int hash_size_tmp1;
    unsigned int hash_size_tmp2;
    unsigned int x;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ctx = EVP_MD_CTX_new();
#else
    ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
#endif
    alg = EVP_sha1();
    hash_size_tmp1 = 0;
    hash_size_tmp2 = 0;
    uint8_t hash_tmp1[EVP_MAX_MD_SIZE];
    uint8_t hash_tmp2[EVP_MAX_MD_SIZE];

    /* First hash the password. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, (unsigned char *)(password), password_len);
    EVP_DigestFinal_ex(ctx, hash_tmp1, &hash_size_tmp1);

    /* Second, hash the password hash. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, hash_tmp1, (size_t)hash_size_tmp1);
    EVP_DigestFinal_ex(ctx, hash_tmp2, &hash_size_tmp2);

    /* Third, hash the scramble and the double password hash. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, (unsigned char *)scramble, SCRAMBLE_LEN);
    EVP_DigestUpdate(ctx, hash_tmp2, (size_t)hash_size_tmp2);
    EVP_DigestFinal_ex(ctx, buffer, buffer_len);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_destroy(ctx);
#endif

    /* Fourth, xor the last hash against the first password hash. */
    for (x = 0; x < *buffer_len; x++) {
        buffer[x] = buffer[x] ^ hash_tmp1[x];
    }
}

static void trilogy_pack_scramble_sha2_hash(const char *scramble, const char *password, size_t password_len,
                                            uint8_t *buffer, unsigned int *buffer_len)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *alg;
    unsigned int hash_size_tmp1;
    unsigned int hash_size_tmp2;
    unsigned int x;

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ctx = EVP_MD_CTX_new();
#else
    ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);
#endif
    alg = EVP_sha256();
    hash_size_tmp1 = 0;
    hash_size_tmp2 = 0;
    uint8_t hash_tmp1[EVP_MAX_MD_SIZE];
    uint8_t hash_tmp2[EVP_MAX_MD_SIZE];

    /* First hash the password. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, (unsigned char *)(password), password_len);
    EVP_DigestFinal_ex(ctx, hash_tmp1, &hash_size_tmp1);

    /* Second, hash the password hash. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, hash_tmp1, (size_t)hash_size_tmp1);
    EVP_DigestFinal_ex(ctx, hash_tmp2, &hash_size_tmp2);

    /* Third, hash the scramble and the double password hash. */
    EVP_DigestInit_ex(ctx, alg, NULL);
    EVP_DigestUpdate(ctx, hash_tmp2, (size_t)hash_size_tmp2);
    EVP_DigestUpdate(ctx, (unsigned char *)scramble, SCRAMBLE_LEN);
    EVP_DigestFinal_ex(ctx, buffer, buffer_len);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    EVP_MD_CTX_free(ctx);
#else
    EVP_MD_CTX_destroy(ctx);
#endif

    /* Fourth, xor the first and last hash. */
    for (x = 0; x < *buffer_len; x++) {
        buffer[x] = hash_tmp1[x] ^ buffer[x];
    }
}

int trilogy_build_auth_packet(trilogy_builder_t *builder, const char *user, const char *pass, size_t pass_len,
                              const char *database, const char *auth_plugin, const char *scramble,
                              TRILOGY_CAPABILITIES_t flags)
{
    int rc = TRILOGY_OK;

    const char *default_auth_plugin = "mysql_native_password";

    uint32_t capabilities = flags;
    // Add the default set of capabilities for this client
    capabilities |= TRILOGY_CAPABILITIES_CLIENT;

    uint32_t max_packet_len = TRILOGY_MAX_PACKET_LEN;

    uint8_t client_encoding = TRILOGY_CHARSET_UTF8_GENERAL_CI;

    unsigned int auth_response_len = 0;
    uint8_t auth_response[EVP_MAX_MD_SIZE];

    if (database) {
        capabilities |= TRILOGY_CAPABILITIES_CONNECT_WITH_DB;
    }

    CHECKED(trilogy_builder_write_uint32(builder, capabilities));

    CHECKED(trilogy_builder_write_uint32(builder, max_packet_len));

    CHECKED(trilogy_builder_write_uint8(builder, client_encoding));

    static const char zeroes[23] = {0};
    CHECKED(trilogy_builder_write_buffer(builder, zeroes, 23));

    if (user) {
        CHECKED(trilogy_builder_write_string(builder, user));
    } else {
        CHECKED(trilogy_builder_write_string(builder, "root"));
    }

    if (pass_len > 0) {
        // Fallback to te default unless we have SHA2 requested
        if (!strcmp("caching_sha2_password", auth_plugin)) {
            trilogy_pack_scramble_sha2_hash(scramble, pass, pass_len, auth_response, &auth_response_len);
        } else {
            trilogy_pack_scramble_native_hash(scramble, pass, pass_len, auth_response, &auth_response_len);
            auth_plugin = default_auth_plugin;
        }
    }

    // auth data len
    CHECKED(trilogy_builder_write_uint8(builder, (uint8_t)auth_response_len));

    if (auth_response_len > 0) {
        CHECKED(trilogy_builder_write_buffer(builder, auth_response, auth_response_len));
    }

    if (database) {
        CHECKED(trilogy_builder_write_string(builder, database));
    }

    if (capabilities & TRILOGY_CAPABILITIES_PLUGIN_AUTH) {
        CHECKED(trilogy_builder_write_string(builder, auth_plugin));
    }

    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

int trilogy_build_auth_switch_response_packet(trilogy_builder_t *builder, const char *pass, size_t pass_len,
                                              const char *auth_plugin, const char *scramble)
{
    int rc = TRILOGY_OK;
    unsigned int auth_response_len = 0;
    uint8_t auth_response[EVP_MAX_MD_SIZE];

    if (!strcmp("caching_sha2_password", auth_plugin)) {
        trilogy_pack_scramble_sha2_hash(scramble, pass, pass_len, auth_response, &auth_response_len);
    } else {
        trilogy_pack_scramble_native_hash(scramble, pass, pass_len, auth_response, &auth_response_len);
    }

    CHECKED(trilogy_builder_write_buffer(builder, auth_response, auth_response_len));
    trilogy_builder_finalize(builder);

    return TRILOGY_OK;
fail:
    return rc;
}

int trilogy_build_ping_packet(trilogy_builder_t *builder)
{
    int rc = TRILOGY_OK;

    CHECKED(trilogy_builder_write_uint8(builder, TRILOGY_CMD_PING));

    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

int trilogy_build_query_packet(trilogy_builder_t *builder, const char *sql, size_t sql_len)
{
    int rc = TRILOGY_OK;

    CHECKED(trilogy_builder_write_uint8(builder, TRILOGY_CMD_QUERY));

    CHECKED(trilogy_builder_write_buffer(builder, sql, sql_len));

    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

int trilogy_build_change_db_packet(trilogy_builder_t *builder, const char *name, size_t name_len)
{
    int rc = TRILOGY_OK;

    CHECKED(trilogy_builder_write_uint8(builder, TRILOGY_CMD_CHANGE_DB));

    CHECKED(trilogy_builder_write_buffer(builder, name, name_len));

    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

int trilogy_build_quit_packet(trilogy_builder_t *builder)
{
    int rc = TRILOGY_OK;

    CHECKED(trilogy_builder_write_uint8(builder, TRILOGY_CMD_QUIT));

    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

int trilogy_build_ssl_request_packet(trilogy_builder_t *builder, TRILOGY_CAPABILITIES_t flags)
{
    static const char zeroes[23] = {0};

    const uint32_t max_packet_len = TRILOGY_MAX_PACKET_LEN;
    const uint8_t client_encoding = TRILOGY_CHARSET_UTF8_GENERAL_CI;
    const uint32_t capabilities = flags | TRILOGY_CAPABILITIES_CLIENT | TRILOGY_CAPABILITIES_SSL;

    int rc = TRILOGY_OK;

    CHECKED(trilogy_builder_write_uint32(builder, capabilities));
    CHECKED(trilogy_builder_write_uint32(builder, max_packet_len));
    CHECKED(trilogy_builder_write_uint8(builder, client_encoding));
    CHECKED(trilogy_builder_write_buffer(builder, zeroes, 23));
    trilogy_builder_finalize(builder);

    return TRILOGY_OK;

fail:
    return rc;
}

#undef CHECKED
