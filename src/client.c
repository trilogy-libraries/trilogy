#include <fcntl.h>

#include "trilogy/client.h"
#include "trilogy/error.h"

#define CHECKED(expr)                                                                                                  \
    if ((rc = (expr)) < 0) {                                                                                           \
        return rc;                                                                                                     \
    }

static inline TRILOGY_PACKET_TYPE_t current_packet_type(trilogy_conn_t *conn)
{
    return (TRILOGY_PACKET_TYPE_t)conn->packet_buffer.buff[0];
}

static int on_packet_begin(void *opaque)
{
    trilogy_buffer_t *buff = opaque;

    buff->len = 0;

    return 0;
}

static int on_packet_data(void *opaque, const uint8_t *data, size_t len)
{
    trilogy_buffer_t *buff = opaque;
    int rc = TRILOGY_OK;

    rc = trilogy_buffer_expand(buff, len);
    if (rc < 0)
        return rc;

    memcpy(buff->buff + buff->len, data, len);
    buff->len += len;

    return 0;
}

static int on_packet_end(void *opaque)
{
    (void)opaque;

    // pause packet parsing so we can return the packet we just read to the
    // caller
    return 1;
}

static trilogy_packet_parser_callbacks_t packet_parser_callbacks = {
    .on_packet_begin = on_packet_begin,
    .on_packet_data = on_packet_data,
    .on_packet_end = on_packet_end,
};

static int begin_command_phase(trilogy_builder_t *builder, trilogy_conn_t *conn, uint8_t seq)
{
    int rc = trilogy_builder_init(builder, &conn->packet_buffer, seq);
    if (rc < 0) {
        return rc;
    }

    if (conn->socket->opts.max_allowed_packet > 0) {
        trilogy_builder_set_max_packet_length(builder, conn->socket->opts.max_allowed_packet);
    }

    conn->packet_parser.sequence_number = seq + 1;

    return 0;
}

static int read_packet(trilogy_conn_t *conn)
{
    if (conn->recv_buff_pos == conn->recv_buff_len) {
        ssize_t nread = trilogy_sock_read(conn->socket, conn->recv_buff, sizeof(conn->recv_buff));

        if (nread < 0) {
            int rc = (int)nread;
            return rc;
        }

        if (nread == 0) {
            return TRILOGY_CLOSED_CONNECTION;
        }

        conn->recv_buff_len = (size_t)nread;
        conn->recv_buff_pos = 0;
    }

    const uint8_t *ptr = conn->recv_buff + conn->recv_buff_pos;
    size_t len = conn->recv_buff_len - conn->recv_buff_pos;

    int rc;
    conn->recv_buff_pos += trilogy_packet_parser_execute(&conn->packet_parser, ptr, len, &rc);

    if (rc < 0) {
        // an error occurred in one of the callbacks
        return rc;
    }

    if (rc > 0) {
        // on_packet_end paused the parser, meaning we read a complete packet
        return TRILOGY_OK;
    }

    // we didn't read a complete packet yet, return TRILOGY_AGAIN so the caller
    // can retry
    return TRILOGY_AGAIN;
}

static int begin_write(trilogy_conn_t *conn)
{
    conn->packet_buffer_written = 0;

    // perform a single write(2), if this does not end up writing the entire
    // packet buffer, then we'll end up returning TRILOGY_AGAIN here and it'll be
    // up to the caller to pump trilogy_flush_writes() until it returns TRILOGY_OK
    return trilogy_flush_writes(conn);
}

int trilogy_init(trilogy_conn_t *conn)
{
    int rc;

    conn->affected_rows = 0;
    conn->last_insert_id = 0;
    conn->warning_count = 0;
    conn->last_gtid_len = 0;

    memset(conn->last_gtid, 0, TRILOGY_MAX_LAST_GTID_LEN);
    conn->error_code = 0;
    conn->error_message = NULL;
    conn->error_message_len = 0;

    conn->capabilities = 0;
    conn->server_status = 0;

    conn->socket = NULL;

    conn->recv_buff_pos = 0;
    conn->recv_buff_len = 0;

    trilogy_packet_parser_init(&conn->packet_parser, &packet_parser_callbacks);
    conn->packet_parser.user_data = &conn->packet_buffer;

    CHECKED(trilogy_buffer_init(&conn->packet_buffer, TRILOGY_DEFAULT_BUF_SIZE));

    return TRILOGY_OK;
}

int trilogy_flush_writes(trilogy_conn_t *conn)
{
    void *ptr = conn->packet_buffer.buff + conn->packet_buffer_written;
    size_t len = conn->packet_buffer.len - conn->packet_buffer_written;

    ssize_t bytes = trilogy_sock_write(conn->socket, ptr, len);

    if (bytes < 0) {
        int rc = (int)bytes;
        return rc;
    }

    conn->packet_buffer_written += (size_t)bytes;

    if (conn->packet_buffer_written < conn->packet_buffer.len) {
        return TRILOGY_AGAIN;
    }

    return TRILOGY_OK;
}

static void set_error(trilogy_conn_t *conn, const trilogy_err_packet_t *packet)
{
    conn->error_code = packet->error_code;
    conn->error_message = packet->error_message;
    conn->error_message_len = packet->error_message_len;
}

static int read_ok_packet(trilogy_conn_t *conn)
{
    trilogy_ok_packet_t ok_packet;

    int rc = trilogy_parse_ok_packet(conn->packet_buffer.buff, conn->packet_buffer.len, conn->capabilities, &ok_packet);

    if (rc != TRILOGY_OK) {
        return rc;
    }

    if (conn->capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41) {
        conn->warning_count = ok_packet.warning_count;
        conn->server_status = ok_packet.status_flags;
    }

    conn->affected_rows = ok_packet.affected_rows;
    conn->last_insert_id = ok_packet.last_insert_id;

    if (ok_packet.last_gtid_len > 0 && ok_packet.last_gtid_len < TRILOGY_MAX_LAST_GTID_LEN) {
        memcpy(conn->last_gtid, ok_packet.last_gtid, ok_packet.last_gtid_len);
        conn->last_gtid_len = ok_packet.last_gtid_len;
    }

    return TRILOGY_OK;
}

static int read_err_packet(trilogy_conn_t *conn)
{
    trilogy_err_packet_t err_packet;

    int rc =
        trilogy_parse_err_packet(conn->packet_buffer.buff, conn->packet_buffer.len, conn->capabilities, &err_packet);

    if (rc != TRILOGY_OK) {
        return rc;
    }

    set_error(conn, &err_packet);

    return TRILOGY_ERR;
}

static int read_eof_packet(trilogy_conn_t *conn)
{
    trilogy_eof_packet_t eof_packet;

    int rc =
        trilogy_parse_eof_packet(conn->packet_buffer.buff, conn->packet_buffer.len, conn->capabilities, &eof_packet);

    if (rc != TRILOGY_OK) {
        return rc;
    }

    if (conn->capabilities & TRILOGY_CAPABILITIES_PROTOCOL_41) {
        conn->warning_count = eof_packet.warning_count;
        conn->server_status = eof_packet.status_flags;
    }

    return TRILOGY_EOF;
}

static int read_auth_switch_packet(trilogy_conn_t *conn, trilogy_handshake_t *handshake)
{
    trilogy_auth_switch_request_packet_t auth_switch_packet;

    int rc = trilogy_parse_auth_switch_request_packet(conn->packet_buffer.buff, conn->packet_buffer.len,
                                                      conn->capabilities, &auth_switch_packet);

    if (rc != TRILOGY_OK) {
        return rc;
    }

    if (strcmp("mysql_native_password", auth_switch_packet.auth_plugin) &&
        strcmp("caching_sha2_password", auth_switch_packet.auth_plugin) &&
        strcmp("mysql_clear_password", auth_switch_packet.auth_plugin)) {
        // Only support native password, caching sha2 and cleartext password here.
        return TRILOGY_PROTOCOL_VIOLATION;
    }

    memcpy(handshake->auth_plugin, auth_switch_packet.auth_plugin, sizeof(auth_switch_packet.auth_plugin));
    memcpy(handshake->scramble, auth_switch_packet.scramble, sizeof(auth_switch_packet.scramble));
    return TRILOGY_AUTH_SWITCH;
}

static int handle_generic_response(trilogy_conn_t *conn) {
    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_OK:
        return read_ok_packet(conn);

    case TRILOGY_PACKET_ERR:
        return read_err_packet(conn);

    default:
        return TRILOGY_UNEXPECTED_PACKET;
    }
}

static int read_generic_response(trilogy_conn_t *conn)
{
    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    return handle_generic_response(conn);
}

int trilogy_connect_send(trilogy_conn_t *conn, const trilogy_sockopt_t *opts)
{
    trilogy_sock_t *sock = trilogy_sock_new(opts);
    if (sock == NULL) {
        return TRILOGY_ERR;
    }

    int rc = trilogy_sock_resolve(sock);
    if (rc < 0) {
        return rc;
    }

    return trilogy_connect_send_socket(conn, sock);
}

int trilogy_connect_send_socket(trilogy_conn_t *conn, trilogy_sock_t *sock)
{
    int rc = trilogy_sock_connect(sock);
    if (rc < 0)
        return rc;

    conn->socket = sock;
    conn->packet_parser.sequence_number = 0;

    return TRILOGY_OK;
}

int trilogy_connect_recv(trilogy_conn_t *conn, trilogy_handshake_t *handshake_out)
{
    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    // In rare cases, the server will actually send an error packet as the
    // initial packet instead of a handshake packet. For example, if there are
    // too many connected clients already.
    if (current_packet_type(conn) == TRILOGY_PACKET_ERR) {
        return read_err_packet(conn);
    }

    rc = trilogy_parse_handshake_packet(conn->packet_buffer.buff, conn->packet_buffer.len, handshake_out);

    if (rc < 0) {
        return rc;
    }

    conn->capabilities = handshake_out->capabilities;
    conn->server_status = handshake_out->server_status;

    return TRILOGY_OK;
}

int trilogy_auth_send(trilogy_conn_t *conn, const trilogy_handshake_t *handshake)
{
    trilogy_builder_t builder;

    int rc = begin_command_phase(&builder, conn, conn->packet_parser.sequence_number);

    if (rc < 0) {
        return rc;
    }

    rc = trilogy_build_auth_packet(&builder, conn->socket->opts.username, conn->socket->opts.password,
                                   conn->socket->opts.password_len, conn->socket->opts.database,
                                   conn->socket->opts.encoding, handshake->auth_plugin, handshake->scramble,
                                   conn->socket->opts.flags);

    if (rc < 0) {
        return rc;
    }

    return begin_write(conn);
}

int trilogy_ssl_request_send(trilogy_conn_t *conn)
{
    trilogy_builder_t builder;

    int rc = begin_command_phase(&builder, conn, conn->packet_parser.sequence_number);

    if (rc < 0) {
        return rc;
    }

    conn->socket->opts.flags |= TRILOGY_CAPABILITIES_SSL;
    rc = trilogy_build_ssl_request_packet(&builder, conn->socket->opts.flags, conn->socket->opts.encoding);

    if (rc < 0) {
        return rc;
    }

    return begin_write(conn);
}

int trilogy_auth_switch_send(trilogy_conn_t *conn, const trilogy_handshake_t *handshake)
{
    trilogy_builder_t builder;

    int rc = begin_command_phase(&builder, conn, conn->packet_parser.sequence_number);

    if (rc < 0) {
        return rc;
    }

    rc = trilogy_build_auth_switch_response_packet(&builder, conn->socket->opts.password,
                                                   conn->socket->opts.password_len, handshake->auth_plugin,
                                                   handshake->scramble, conn->socket->opts.enable_cleartext_plugin);

    if (rc < 0) {
        return rc;
    }

    return begin_write(conn);
}

void trilogy_auth_clear_password(trilogy_conn_t *conn)
{
    if (conn->socket->opts.password) {
        memset(conn->socket->opts.password, 0, conn->socket->opts.password_len);
    }
}

#define FAST_AUTH_OK 3
#define FAST_AUTH_FAIL 4

int trilogy_auth_recv(trilogy_conn_t *conn, trilogy_handshake_t *handshake)
{
    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_AUTH_MORE_DATA: {
        bool use_ssl = (conn->socket->opts.flags & TRILOGY_CAPABILITIES_SSL) != 0;
        bool has_unix_socket = (conn->socket->opts.path != NULL);

        if (!use_ssl && !has_unix_socket) {
            return TRILOGY_UNSUPPORTED;
        }

        uint8_t byte = conn->packet_buffer.buff[1];
        switch (byte) {
            case FAST_AUTH_OK:
                break;
            case FAST_AUTH_FAIL:
                {
                    trilogy_builder_t builder;
                    int err = begin_command_phase(&builder, conn, conn->packet_parser.sequence_number);

                    if (err < 0) {
                        return err;
                    }

                    err = trilogy_build_auth_clear_password(&builder, conn->socket->opts.password, conn->socket->opts.password_len);

                    if (err < 0) {
                        return err;
                    }

                    int rc = begin_write(conn);

                    while (rc == TRILOGY_AGAIN) {
                        rc = trilogy_sock_wait_write(conn->socket);
                        if (rc != TRILOGY_OK) {
                            return rc;
                        }

                        rc = trilogy_flush_writes(conn);
                    }
                    if (rc != TRILOGY_OK) {
                        return rc;
                    }

                    break;
                }
            default:
                return TRILOGY_UNEXPECTED_PACKET;
        }
        while (1) {
            rc = read_packet(conn);

            if (rc == TRILOGY_OK) {
                break;
            }
            else if (rc == TRILOGY_AGAIN) {
                rc = trilogy_sock_wait_read(conn->socket);
            }

            if (rc != TRILOGY_OK) {
                return rc;
            }
        }
        trilogy_auth_clear_password(conn);
        return handle_generic_response(conn);
    }

    case TRILOGY_PACKET_EOF:
        // EOF is returned here if an auth switch is requested.
        // We still need the password for the switch, it will be cleared
        // in a follow up call to this function after the switch.
        return read_auth_switch_packet(conn, handshake);

    case TRILOGY_PACKET_OK:
    case TRILOGY_PACKET_ERR:
    default:
        trilogy_auth_clear_password(conn);
        return handle_generic_response(conn);
    }

    return read_generic_response(conn);
}

int trilogy_change_db_send(trilogy_conn_t *conn, const char *name, size_t name_len)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_change_db_packet(&builder, name, name_len);

    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_change_db_recv(trilogy_conn_t *conn) { return read_generic_response(conn); }

int trilogy_set_option_send(trilogy_conn_t *conn, const uint16_t option)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_set_option_packet(&builder, option);

    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_set_option_recv(trilogy_conn_t *conn) {
    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_OK:
    case TRILOGY_PACKET_EOF: // COM_SET_OPTION returns an EOF packet, but it should be treated as an OK packet.
        return read_ok_packet(conn);

    case TRILOGY_PACKET_ERR:
        return read_err_packet(conn);

    default:
        return TRILOGY_UNEXPECTED_PACKET;
    }
}


int trilogy_ping_send(trilogy_conn_t *conn)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_ping_packet(&builder);

    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_ping_recv(trilogy_conn_t *conn) { return read_generic_response(conn); }

int trilogy_query_send(trilogy_conn_t *conn, const char *query, size_t query_len)
{
    int err = 0;

    trilogy_builder_t builder;
    err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_query_packet(&builder, query, query_len);
    if (err < 0) {
        return err;
    }

    conn->packet_parser.sequence_number = builder.seq;

    return begin_write(conn);
}

int trilogy_query_recv(trilogy_conn_t *conn, uint64_t *column_count_out)
{
    int err = read_packet(conn);

    if (err < 0) {
        return err;
    }

    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_OK:
        return read_ok_packet(conn);

    case TRILOGY_PACKET_ERR:
        return read_err_packet(conn);

    default: {
        trilogy_result_packet_t result_packet;
        err = trilogy_parse_result_packet(conn->packet_buffer.buff, conn->packet_buffer.len, &result_packet);

        if (err < 0) {
            return err;
        }

        conn->column_count = result_packet.column_count;
        *column_count_out = result_packet.column_count;
        conn->started_reading_rows = false;

        return TRILOGY_HAVE_RESULTS;
    }
    }
}

int trilogy_read_column(trilogy_conn_t *conn, trilogy_column_t *column_out)
{
    int err = read_packet(conn);

    if (err < 0) {
        return err;
    }

    return trilogy_parse_column_packet(conn->packet_buffer.buff, conn->packet_buffer.len, 0, column_out);
}

static int read_eof(trilogy_conn_t *conn)
{
    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    if (conn->capabilities & TRILOGY_CAPABILITIES_DEPRECATE_EOF) {
        return read_ok_packet(conn);
    } else {
        if ((rc = read_eof_packet(conn)) != TRILOGY_EOF) {
            return rc;
        }

        return TRILOGY_OK;
    }
}

int trilogy_read_row(trilogy_conn_t *conn, trilogy_value_t *values_out)
{
    if (!conn->started_reading_rows) {
        if ((conn->capabilities & TRILOGY_CAPABILITIES_DEPRECATE_EOF) == 0) {
            // we need to skip over the EOF packet that arrives after the column
            // packets
            int rc = read_eof(conn);

            if (rc < 0) {
                return rc;
            }
        }

        conn->started_reading_rows = true;
    }

    int rc = read_packet(conn);

    if (rc < 0) {
        return rc;
    }

    if (conn->capabilities & TRILOGY_CAPABILITIES_DEPRECATE_EOF && current_packet_type(conn) == TRILOGY_PACKET_EOF) {
        if ((rc = read_ok_packet(conn)) != TRILOGY_OK) {
            return rc;
        }

        return TRILOGY_EOF;
    } else if (current_packet_type(conn) == TRILOGY_PACKET_EOF && conn->packet_buffer.len < 9) {
        return read_eof_packet(conn);
    } else if (current_packet_type(conn) == TRILOGY_PACKET_ERR) {
        return read_err_packet(conn);
    } else {
        return trilogy_parse_row_packet(conn->packet_buffer.buff, conn->packet_buffer.len, conn->column_count,
                                        values_out);
    }
}

int trilogy_drain_results(trilogy_conn_t *conn)
{
    if (!conn->started_reading_rows) {
        // we need to skip over the EOF packet that arrives after the column
        // packets
        int rc = read_eof(conn);

        if (rc < 0) {
            return rc;
        }

        conn->started_reading_rows = true;
    }

    while (1) {
        int rc = read_packet(conn);

        if (rc < 0) {
            return rc;
        }

        if (current_packet_type(conn) == TRILOGY_PACKET_EOF && conn->packet_buffer.len < 9) {
            return TRILOGY_OK;
        }
    }
}

static uint8_t escape_lookup_table[256] = {
    ['"'] = '"', ['\0'] = '0', ['\''] = '\'', ['\\'] = '\\', ['\n'] = 'n', ['\r'] = 'r', [26] = 'Z',
};

int trilogy_escape(trilogy_conn_t *conn, const char *str, size_t len, const char **escaped_str_out,
                   size_t *escaped_len_out)
{
    int rc;

    trilogy_buffer_t *b = &conn->packet_buffer;

    b->len = 0;

    if (conn->server_status & TRILOGY_SERVER_STATUS_NO_BACKSLASH_ESCAPES) {
        for (size_t i = 0; i < len; i++) {
            const uint8_t c = (uint8_t)str[i];

            if (c == '\'') {
                CHECKED(trilogy_buffer_putc(b, '\''));
                CHECKED(trilogy_buffer_putc(b, '\''));
            } else {
                CHECKED(trilogy_buffer_putc(b, c));
            }
        }
    } else {
        for (size_t i = 0; i < len; i++) {
            const uint8_t c = (uint8_t)str[i];

            uint8_t escaped = escape_lookup_table[(uint8_t)c];

            if (escaped) {
                CHECKED(trilogy_buffer_putc(b, '\\'));
                CHECKED(trilogy_buffer_putc(b, escaped));
            } else {
                CHECKED(trilogy_buffer_putc(b, c));
            }
        }
    }

    *escaped_str_out = (const char *)b->buff;
    *escaped_len_out = b->len;

    return TRILOGY_OK;
}

int trilogy_close_send(trilogy_conn_t *conn)
{
    trilogy_builder_t builder;
    int rc = begin_command_phase(&builder, conn, 0);
    if (rc < 0) {
        return rc;
    }

    rc = trilogy_build_quit_packet(&builder);

    if (rc < 0) {
        return rc;
    }

    return begin_write(conn);
}

int trilogy_close_recv(trilogy_conn_t *conn)
{
    trilogy_sock_shutdown(conn->socket);

    int rc = read_packet(conn);

    switch (rc) {
    case TRILOGY_CLOSED_CONNECTION:
        return TRILOGY_OK;

    case TRILOGY_OK:
        // we need to handle TRILOGY_OK specially and translate it into
        // TRILOGY_PROTOCOL_VIOLATION so we don't end up returning TRILOGY_OK
        // in the default case
        return TRILOGY_PROTOCOL_VIOLATION;

    default:
        return rc;
    }
}

void trilogy_free(trilogy_conn_t *conn)
{
    if (conn->socket != NULL) {
        trilogy_sock_close(conn->socket);
        conn->socket = NULL;
    }

    trilogy_buffer_free(&conn->packet_buffer);
}

int trilogy_discard(trilogy_conn_t *conn)
{
    int rc = trilogy_sock_shutdown(conn->socket);
    if (rc == TRILOGY_OK) {
        trilogy_free(conn);
    }
    return rc;
}

int trilogy_stmt_prepare_send(trilogy_conn_t *conn, const char *stmt, size_t stmt_len)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_stmt_prepare_packet(&builder, stmt, stmt_len);
    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_stmt_prepare_recv(trilogy_conn_t *conn, trilogy_stmt_t *stmt_out)
{
    int err = read_packet(conn);

    if (err < 0) {
        return err;
    }

    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_OK: {
        err = trilogy_parse_stmt_ok_packet(conn->packet_buffer.buff, conn->packet_buffer.len, stmt_out);

        if (err < 0) {
            return err;
        }

        conn->warning_count = stmt_out->warning_count;

        return TRILOGY_OK;
    }

    case TRILOGY_PACKET_ERR:
        return read_err_packet(conn);

    default:
        return TRILOGY_UNEXPECTED_PACKET;
    }
}

int trilogy_stmt_execute_send(trilogy_conn_t *conn, trilogy_stmt_t *stmt, uint8_t flags, trilogy_binary_value_t *binds)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_stmt_execute_packet(&builder, stmt->id, flags, binds, stmt->parameter_count);

    if (err < 0) {
        return err;
    }

    conn->packet_parser.sequence_number = builder.seq;

    return begin_write(conn);
}

int trilogy_stmt_execute_recv(trilogy_conn_t *conn, uint64_t *column_count_out)
{
    int err = read_packet(conn);

    if (err < 0) {
        return err;
    }

    switch (current_packet_type(conn)) {
    case TRILOGY_PACKET_OK:
        return read_ok_packet(conn);

    case TRILOGY_PACKET_ERR:
        return read_err_packet(conn);

    default: {
        trilogy_result_packet_t result_packet;
        err = trilogy_parse_result_packet(conn->packet_buffer.buff, conn->packet_buffer.len, &result_packet);

        if (err < 0) {
            return err;
        }

        conn->column_count = result_packet.column_count;
        *column_count_out = result_packet.column_count;

        return TRILOGY_OK;
    }
    }
}

int trilogy_stmt_bind_data_send(trilogy_conn_t *conn, trilogy_stmt_t *stmt, uint16_t param_num, uint8_t *data,
                                size_t data_len)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_stmt_bind_data_packet(&builder, stmt->id, param_num, data, data_len);

    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_stmt_read_row(trilogy_conn_t *conn, trilogy_stmt_t *stmt, trilogy_column_packet_t *columns,
                          trilogy_binary_value_t *values_out)
{
    int err = read_packet(conn);

    if (err < 0) {
        return err;
    }

    if (conn->capabilities & TRILOGY_CAPABILITIES_DEPRECATE_EOF && current_packet_type(conn) == TRILOGY_PACKET_EOF) {
        if ((err = read_ok_packet(conn)) != TRILOGY_OK) {
            return err;
        }

        return TRILOGY_EOF;
    } else if (current_packet_type(conn) == TRILOGY_PACKET_EOF && conn->packet_buffer.len < 9) {
        return read_eof_packet(conn);
    } else if (current_packet_type(conn) == TRILOGY_PACKET_ERR) {
        return read_err_packet(conn);
    } else {
        return trilogy_parse_stmt_row_packet(conn->packet_buffer.buff, conn->packet_buffer.len, columns,
                                             stmt->column_count, values_out);
    }
}

int trilogy_stmt_reset_send(trilogy_conn_t *conn, trilogy_stmt_t *stmt)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_stmt_reset_packet(&builder, stmt->id);
    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

int trilogy_stmt_reset_recv(trilogy_conn_t *conn) {
    return read_generic_response(conn);
}

int trilogy_stmt_close_send(trilogy_conn_t *conn, trilogy_stmt_t *stmt)
{
    trilogy_builder_t builder;
    int err = begin_command_phase(&builder, conn, 0);
    if (err < 0) {
        return err;
    }

    err = trilogy_build_stmt_close_packet(&builder, stmt->id);

    if (err < 0) {
        return err;
    }

    return begin_write(conn);
}

#undef CHECKED
