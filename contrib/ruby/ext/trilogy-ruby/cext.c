#include <arpa/inet.h>
#include <errno.h>
#include <ruby.h>
#include <ruby/encoding.h>
#include <ruby/io.h>
#include <ruby/thread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include <trilogy.h>

#include "trilogy-ruby.h"

#define TRILOGY_RB_TIMEOUT 1

VALUE
rb_cTrilogyError;

static VALUE Trilogy_DatabaseError, Trilogy_Result;

static ID id_socket, id_host, id_port, id_username, id_password, id_found_rows, id_connect_timeout, id_read_timeout,
    id_write_timeout, id_keepalive_enabled, id_keepalive_idle, id_keepalive_interval, id_keepalive_count,
    id_ivar_affected_rows, id_ivar_fields, id_ivar_last_insert_id, id_ivar_rows, id_ivar_query_time, id_password,
    id_database, id_ssl_ca, id_ssl_capath, id_ssl_cert, id_ssl_cipher, id_ssl_crl, id_ssl_crlpath, id_ssl_key,
    id_ssl_mode, id_tls_ciphersuites, id_tls_min_version, id_tls_max_version;

struct trilogy_ctx {
    trilogy_conn_t conn;
    char server_version[TRILOGY_SERVER_VERSION_SIZE + 1];
    unsigned int query_flags;
};

static struct trilogy_ctx *get_ctx(VALUE obj)
{
    struct trilogy_ctx *ctx;
    Data_Get_Struct(obj, struct trilogy_ctx, ctx);
    return ctx;
}

static struct trilogy_ctx *get_open_ctx(VALUE obj)
{
    struct trilogy_ctx *ctx = get_ctx(obj);

    if (ctx->conn.socket == NULL) {
        rb_raise(rb_eIOError, "connection closed");
    }

    return ctx;
}

NORETURN(static void handle_trilogy_error(struct trilogy_ctx *, int, const char *, ...));
static void handle_trilogy_error(struct trilogy_ctx *ctx, int rc, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    VALUE rbmsg = rb_vsprintf(msg, args);
    va_end(args);

    switch (rc) {
    case TRILOGY_SYSERR:
        rb_syserr_fail_str(errno, rbmsg);

    case TRILOGY_ERR: {
        VALUE message = rb_str_new(ctx->conn.error_message, ctx->conn.error_message_len);
        VALUE exc = rb_exc_new3(Trilogy_DatabaseError,
                                rb_sprintf("%" PRIsVALUE ": %d %" PRIsVALUE, rbmsg, ctx->conn.error_code, message));

        rb_ivar_set(exc, rb_intern("@error_code"), INT2FIX(ctx->conn.error_code));
        rb_ivar_set(exc, rb_intern("@error_message"), message);

        rb_exc_raise(exc);
    }

    case TRILOGY_OPENSSL_ERR: {
        unsigned long ossl_error = ERR_get_error();
        ERR_clear_error();
        if (ERR_GET_LIB(ossl_error) == ERR_LIB_SYS) {
            rb_syserr_fail_str(ERR_GET_REASON(ossl_error), rbmsg);
        }
        // We can't recover from OpenSSL level errors if there's
        // an active connection.
        if (ctx->conn.socket != NULL) {
            trilogy_sock_shutdown(ctx->conn.socket);
        }
        rb_raise(rb_cTrilogyError, "%" PRIsVALUE ": SSL Error: %s", rbmsg, ERR_reason_error_string(ossl_error));
    }

    default:
        rb_raise(rb_cTrilogyError, "%" PRIsVALUE ": %s", rbmsg, trilogy_error(rc));
    }
}

static void free_trilogy(struct trilogy_ctx *ctx)
{
    if (ctx->conn.socket != NULL) {
        trilogy_free(&ctx->conn);
    }
}

static VALUE allocate_trilogy(VALUE klass)
{
    struct trilogy_ctx *ctx;

    VALUE obj = Data_Make_Struct(klass, struct trilogy_ctx, NULL, free_trilogy, ctx);

    memset(ctx->server_version, 0, sizeof(ctx->server_version));

    ctx->query_flags = TRILOGY_FLAGS_DEFAULT;

    if (trilogy_init(&ctx->conn) < 0) {
        rb_syserr_fail(errno, "trilogy_init");
    }

    return obj;
}

static int flush_writes(struct trilogy_ctx *ctx)
{
    while (1) {
        int rc = trilogy_flush_writes(&ctx->conn);

        if (rc != TRILOGY_AGAIN) {
            return rc;
        }

        if (trilogy_sock_wait_write(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_flush_writes");
        }
    }
}

static struct timeval double_to_timeval(double secs)
{
    double whole_secs = floor(secs);

    return (struct timeval){
        .tv_sec = whole_secs,
        .tv_usec = floor((secs - whole_secs) * 1000000),
    };
}

static int _cb_ruby_wait(trilogy_sock_t *sock, trilogy_wait_t wait)
{
    struct timeval *timeout = NULL;
    int wait_flag = 0;

    switch (wait) {
    case TRILOGY_WAIT_READ:
        timeout = &sock->opts.read_timeout;
        wait_flag = RB_WAITFD_IN;
        break;

    case TRILOGY_WAIT_WRITE:
        timeout = &sock->opts.write_timeout;
        wait_flag = RB_WAITFD_OUT;
        break;

    case TRILOGY_WAIT_HANDSHAKE:
        timeout = &sock->opts.connect_timeout;
        wait_flag = RB_WAITFD_IN;
        break;

    default:
        return TRILOGY_ERR;
    }

    if (timeout->tv_sec == 0 && timeout->tv_usec == 0) {
        timeout = NULL;
    }

    int fd = trilogy_sock_fd(sock);
    if (rb_wait_for_single_fd(fd, wait_flag, timeout) <= 0)
        return TRILOGY_SYSERR;

    return 0;
}

struct nogvl_sock_args {
    int rc;
    trilogy_sock_t *sock;
};

static void *no_gvl_resolve(void *data)
{
    struct nogvl_sock_args *args = data;
    args->rc = trilogy_sock_resolve(args->sock);
    return NULL;
}

static int try_connect(struct trilogy_ctx *ctx, trilogy_handshake_t *handshake, const trilogy_sockopt_t *opts)
{
    trilogy_sock_t *sock = trilogy_sock_new(opts);
    if (sock == NULL) {
        return TRILOGY_ERR;
    }

    struct nogvl_sock_args args = {.rc = 0, .sock = sock};

    // Do the DNS resolving with the GVL unlocked. At this point all
    // configuration data is copied and available to the trilogy socket.
    rb_thread_call_without_gvl(no_gvl_resolve, (void *)&args, RUBY_UBF_IO, NULL);

    int rc = args.rc;

    if (rc != TRILOGY_OK) {
        return rc;
    }

    /* replace the default wait callback with our GVL-aware callback so we can
escape the GVL on each wait operation without going through call_without_gvl */
    sock->wait_cb = _cb_ruby_wait;
    rc = trilogy_connect_send_socket(&ctx->conn, sock);
    if (rc < 0)
        return rc;

    while (1) {
        rc = trilogy_connect_recv(&ctx->conn, handshake);

        if (rc == TRILOGY_OK) {
            return rc;
        }

        if (rc != TRILOGY_AGAIN) {
            return rc;
        }

        if (trilogy_sock_wait(ctx->conn.socket, TRILOGY_WAIT_HANDSHAKE) < 0)
            return TRILOGY_RB_TIMEOUT;
    }
}

static void auth_switch(struct trilogy_ctx *ctx, trilogy_handshake_t *handshake)
{
    int rc = trilogy_auth_switch_send(&ctx->conn, handshake);

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc != TRILOGY_OK) {
        handle_trilogy_error(ctx, rc, "trilogy_auth_switch_send");
    }

    while (1) {
        rc = trilogy_auth_recv(&ctx->conn, handshake);

        if (rc == TRILOGY_OK) {
            return;
        }

        if (rc != TRILOGY_AGAIN) {
            handle_trilogy_error(ctx, rc, "trilogy_auth_recv");
        }

        if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_auth_recv");
        }
    }
}

static void authenticate(struct trilogy_ctx *ctx, trilogy_handshake_t *handshake, trilogy_ssl_mode_t ssl_mode)
{
    int rc;

    if (ssl_mode != TRILOGY_SSL_DISABLED) {
        if (handshake->capabilities & TRILOGY_CAPABILITIES_SSL) {
            rc = trilogy_ssl_request_send(&ctx->conn);
            if (rc == TRILOGY_AGAIN) {
                rc = flush_writes(ctx);
            }

            if (rc != TRILOGY_OK) {
                handle_trilogy_error(ctx, rc, "trilogy_ssl_request_send");
            }

            rc = trilogy_sock_upgrade_ssl(ctx->conn.socket);
            if (rc != TRILOGY_OK) {
                handle_trilogy_error(ctx, rc, "trilogy_ssl_upgrade");
            }
        } else {
            if (ssl_mode != TRILOGY_SSL_PREFERRED_NOVERIFY) {
                rb_raise(rb_cTrilogyError, "SSL required, not supported by server");
            }
        }
    }

    rc = trilogy_auth_send(&ctx->conn, handshake);

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc != TRILOGY_OK) {
        handle_trilogy_error(ctx, rc, "trilogy_auth_send");
    }

    while (1) {
        rc = trilogy_auth_recv(&ctx->conn, handshake);

        if (rc == TRILOGY_OK || rc == TRILOGY_AUTH_SWITCH) {
            break;
        }

        if (rc != TRILOGY_AGAIN) {
            handle_trilogy_error(ctx, rc, "trilogy_auth_recv");
        }

        if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_auth_recv");
        }
    }

    if (rc == TRILOGY_AUTH_SWITCH) {
        auth_switch(ctx, handshake);
    }
}

static VALUE rb_trilogy_initialize(VALUE self, VALUE opts)
{
    struct trilogy_ctx *ctx = get_ctx(self);
    trilogy_sockopt_t connopt = {0};
    trilogy_handshake_t handshake;
    VALUE val;

    Check_Type(opts, T_HASH);

    if ((val = rb_hash_lookup(opts, ID2SYM(id_ssl_mode))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.ssl_mode = (trilogy_ssl_mode_t)NUM2INT(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_connect_timeout))) != Qnil) {
        connopt.connect_timeout = double_to_timeval(NUM2DBL(val));
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_read_timeout))) != Qnil) {
        connopt.read_timeout = double_to_timeval(NUM2DBL(val));
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_write_timeout))) != Qnil) {
        connopt.write_timeout = double_to_timeval(NUM2DBL(val));
    }

    if (RTEST(rb_hash_aref(opts, ID2SYM(id_keepalive_enabled)))) {
        connopt.keepalive_enabled = true;
    }

    if ((val = rb_hash_lookup(opts, ID2SYM(id_keepalive_idle))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.keepalive_idle = NUM2USHORT(val);
    }

    if ((val = rb_hash_lookup(opts, ID2SYM(id_keepalive_count))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.keepalive_count = NUM2USHORT(val);
    }

    if ((val = rb_hash_lookup(opts, ID2SYM(id_keepalive_interval))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.keepalive_interval = NUM2USHORT(val);
    }

    if ((val = rb_hash_lookup(opts, ID2SYM(id_host))) != Qnil) {
        Check_Type(val, T_STRING);

        connopt.hostname = StringValueCStr(val);
        connopt.port = 3306;

        if ((val = rb_hash_lookup(opts, ID2SYM(id_port))) != Qnil) {
            Check_Type(val, T_FIXNUM);
            connopt.port = NUM2USHORT(val);
        }
    } else {
        connopt.path = (char *)"/tmp/mysql.sock";

        if ((val = rb_hash_lookup(opts, ID2SYM(id_socket))) != Qnil) {
            Check_Type(val, T_STRING);
            connopt.path = StringValueCStr(val);
        }
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_username))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.username = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_password))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.password = RSTRING_PTR(val);
        connopt.password_len = RSTRING_LEN(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_database))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.database = StringValueCStr(val);
        connopt.flags |= TRILOGY_CAPABILITIES_CONNECT_WITH_DB;
    }

    if (RTEST(rb_hash_aref(opts, ID2SYM(id_found_rows)))) {
        connopt.flags |= TRILOGY_CAPABILITIES_FOUND_ROWS;
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_ca))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_ca = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_capath))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_capath = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_cert))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_cert = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_cipher))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_cipher = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_crl))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_crl = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_crlpath))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_crlpath = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_ssl_key))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.ssl_key = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_tls_ciphersuites))) != Qnil) {
        Check_Type(val, T_STRING);
        connopt.tls_ciphersuites = StringValueCStr(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_tls_min_version))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.tls_min_version = NUM2INT(val);
    }

    if ((val = rb_hash_aref(opts, ID2SYM(id_tls_max_version))) != Qnil) {
        Check_Type(val, T_FIXNUM);
        connopt.tls_max_version = NUM2INT(val);
    }

    int rc = try_connect(ctx, &handshake, &connopt);
    if (rc == TRILOGY_RB_TIMEOUT) {
        rb_syserr_fail(ETIMEDOUT, "trilogy_connect_recv");
    }
    if (rc != TRILOGY_OK) {
        if (connopt.path) {
            handle_trilogy_error(ctx, rc, "trilogy_connect - unable to connect to %s", connopt.path);
        } else {
            handle_trilogy_error(ctx, rc, "trilogy_connect - unable to connect to %s:%hu", connopt.hostname,
                                 connopt.port);
        }
    }

    memcpy(ctx->server_version, handshake.server_version, TRILOGY_SERVER_VERSION_SIZE);
    ctx->server_version[TRILOGY_SERVER_VERSION_SIZE] = 0;

    authenticate(ctx, &handshake, connopt.ssl_mode);

    return Qnil;
}

static VALUE rb_trilogy_change_db(VALUE self, VALUE database)
{
    struct trilogy_ctx *ctx = get_open_ctx(self);

    StringValue(database);

    int rc = trilogy_change_db_send(&ctx->conn, RSTRING_PTR(database), RSTRING_LEN(database));

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc != TRILOGY_OK) {
        handle_trilogy_error(ctx, rc, "trilogy_change_db_send");
    }

    while (1) {
        rc = trilogy_change_db_recv(&ctx->conn);

        if (rc == TRILOGY_OK) {
            break;
        }

        if (rc != TRILOGY_AGAIN) {
            handle_trilogy_error(ctx, rc, "trilogy_change_db_recv");
        }

        if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_change_db_recv");
        }
    }

    return Qtrue;
}

static void load_query_options(unsigned int query_flags, struct rb_trilogy_cast_options *cast_options)
{
    cast_options->cast = (query_flags & TRILOGY_FLAGS_CAST) != 0;
    cast_options->cast_booleans = (query_flags & TRILOGY_FLAGS_CAST_BOOLEANS) != 0;
    cast_options->database_local_time = (query_flags & TRILOGY_FLAGS_LOCAL_TIMEZONE) != 0;
    cast_options->flatten_rows = (query_flags & TRILOGY_FLAGS_FLATTEN_ROWS) != 0;
}

struct read_query_state {
    struct rb_trilogy_cast_options *cast_options;
    struct trilogy_ctx *ctx;
    VALUE query;

    // to free by caller:
    struct column_info *column_info;
    trilogy_value_t *row_values;

    // Error state for tracking
    const char *msg;
    int rc;
};

static void get_timespec_monotonic(struct timespec *ts)
{
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    if (clock_gettime(CLOCK_MONOTONIC, ts) == -1) {
        rb_sys_fail("clock_gettime");
    }
#else
    struct timeval tv;
    if (gettimeofday(&tv, 0) < 0) {
        rb_sys_fail("gettimeofday");
    }
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;
#endif
}

static VALUE read_query_error(struct read_query_state *args, int rc, const char *msg)
{
    args->rc = rc;
    args->msg = msg;
    return Qundef;
}

static VALUE execute_read_query(VALUE vargs)
{
    struct read_query_state *args = (void *)vargs;
    struct trilogy_ctx *ctx = args->ctx;
    VALUE query = args->query;

    struct timespec start;
    get_timespec_monotonic(&start);

    int rc = trilogy_query_send(&ctx->conn, RSTRING_PTR(query), RSTRING_LEN(query));

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc < 0) {
        return read_query_error(args, rc, "trilogy_query_send");
    }

    uint64_t column_count = 0;

    while (1) {
        rc = trilogy_query_recv(&ctx->conn, &column_count);

        if (rc == TRILOGY_OK || rc == TRILOGY_HAVE_RESULTS) {
            break;
        }

        if (rc != TRILOGY_AGAIN) {
            return read_query_error(args, rc, "trilogy_query_recv");
        }

        if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_query_recv");
        }
    }

    struct timespec finish;
    get_timespec_monotonic(&finish);

    double query_time = finish.tv_sec - start.tv_sec;
    query_time += (double)(finish.tv_nsec - start.tv_nsec) / 1000000000.0;

    VALUE result = rb_obj_alloc(Trilogy_Result);

    VALUE column_names = rb_ary_new2(column_count);
    rb_ivar_set(result, id_ivar_fields, column_names);

    VALUE rows = rb_ary_new();
    rb_ivar_set(result, id_ivar_rows, rows);

    rb_ivar_set(result, id_ivar_query_time, DBL2NUM(query_time));

    if (rc == TRILOGY_OK) {
        rb_ivar_set(result, id_ivar_last_insert_id, ULL2NUM(ctx->conn.last_insert_id));

        rb_ivar_set(result, id_ivar_affected_rows, ULL2NUM(ctx->conn.affected_rows));

        return result;
    }

    struct column_info *column_info = ALLOC_N(struct column_info, column_count);
    args->column_info = column_info;

    for (uint64_t i = 0; i < column_count; i++) {
        trilogy_column_t column;

        while (1) {
            rc = trilogy_read_column(&ctx->conn, &column);

            if (rc == TRILOGY_OK) {
                break;
            }

            if (rc != TRILOGY_AGAIN) {
                return read_query_error(args, rc, "trilogy_read_column");
            }

            if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
                rb_syserr_fail(ETIMEDOUT, "trilogy_read_column");
            }
        }

#ifdef HAVE_RB_INTERNED_STR
        VALUE column_name = rb_interned_str(column.name, column.name_len);
#else
        VALUE column_name = rb_str_new(column.name, column.name_len);
        OBJ_FREEZE(column_name);
#endif

        rb_ary_push(column_names, column_name);

        column_info[i].type = column.type;
        column_info[i].flags = column.flags;
        column_info[i].len = column.len;
        column_info[i].charset = column.charset;
    }

    trilogy_value_t *row_values = ALLOC_N(trilogy_value_t, column_count);
    args->row_values = row_values;

    while (1) {
        int rc = trilogy_read_row(&ctx->conn, row_values);

        if (rc == TRILOGY_AGAIN) {
            if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
                rb_syserr_fail(ETIMEDOUT, "trilogy_read_row");
            }
            continue;
        }

        if (rc == TRILOGY_EOF) {
            break;
        }

        if (rc != TRILOGY_OK) {
            return read_query_error(args, rc, "trilogy_read_row");
        }

        if (args->cast_options->flatten_rows) {
            for (uint64_t i = 0; i < column_count; i++) {
                rb_ary_push(rows, rb_trilogy_cast_value(row_values + i, column_info + i, args->cast_options));
            }
        } else {
            VALUE row = rb_ary_new2(column_count);
            for (uint64_t i = 0; i < column_count; i++) {
                rb_ary_push(row, rb_trilogy_cast_value(row_values + i, column_info + i, args->cast_options));
            }
            rb_ary_push(rows, row);
        }
    }

    if (ctx->conn.server_status & TRILOGY_SERVER_STATUS_MORE_RESULTS_EXISTS) {
        rb_raise(rb_cTrilogyError, "MORE_RESULTS_EXIST");
    }

    return result;
}

static VALUE rb_trilogy_query(VALUE self, VALUE query)
{
    struct trilogy_ctx *ctx = get_open_ctx(self);

    StringValue(query);

    struct rb_trilogy_cast_options cast_options;
    load_query_options(ctx->query_flags, &cast_options);

    struct read_query_state args = {
        .cast_options = &cast_options,
        .column_info = NULL,
        .ctx = ctx,
        .query = query,
        .row_values = NULL,
        .rc = TRILOGY_OK,
        .msg = NULL,
    };

    int state = 0;
    VALUE result = rb_protect(execute_read_query, (VALUE)&args, &state);

    xfree(args.column_info);
    xfree(args.row_values);

    // If we have seen an unexpected exception, jump to it so it gets raised.
    if (state) {
        trilogy_sock_shutdown(ctx->conn.socket);
        rb_jump_tag(state);
    }

    // Handle errors we can gracefully recover from here that were due to
    // errors signaled at the protocol level, not unexpected exceptions.
    if (result == Qundef) {
        handle_trilogy_error(ctx, args.rc, args.msg);
    }

    return result;
}

static VALUE rb_trilogy_ping(VALUE self)
{
    struct trilogy_ctx *ctx = get_open_ctx(self);

    int rc = trilogy_ping_send(&ctx->conn);

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc < 0) {
        handle_trilogy_error(ctx, rc, "trilogy_ping_send");
    }

    while (1) {
        rc = trilogy_ping_recv(&ctx->conn);

        if (rc == TRILOGY_OK) {
            break;
        }

        if (rc != TRILOGY_AGAIN) {
            handle_trilogy_error(ctx, rc, "trilogy_ping_recv");
        }

        if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
            rb_syserr_fail(ETIMEDOUT, "trilogy_ping_recv");
        }
    }

    return Qtrue;
}

static VALUE rb_trilogy_escape(VALUE self, VALUE str)
{
    struct trilogy_ctx *ctx = get_open_ctx(self);
    rb_encoding *str_enc = rb_enc_get(str);

    StringValue(str);

    if (!rb_enc_asciicompat(str_enc)) {
        rb_raise(rb_eEncCompatError, "input string must be ASCII-compatible");
    }

    const char *escaped_str;
    size_t escaped_len;

    int rc = trilogy_escape(&ctx->conn, RSTRING_PTR(str), RSTRING_LEN(str), &escaped_str, &escaped_len);

    if (rc < 0) {
        handle_trilogy_error(ctx, rc, "trilogy_escape");
    }

    return rb_enc_str_new(escaped_str, escaped_len, str_enc);
}

static VALUE rb_trilogy_close(VALUE self)
{
    struct trilogy_ctx *ctx = get_ctx(self);

    if (ctx->conn.socket == NULL) {
        return Qnil;
    }

    int rc = trilogy_close_send(&ctx->conn);

    if (rc == TRILOGY_AGAIN) {
        rc = flush_writes(ctx);
    }

    if (rc == TRILOGY_OK) {
        while (1) {
            rc = trilogy_close_recv(&ctx->conn);

            if (rc != TRILOGY_AGAIN) {
                break;
            }

            if (trilogy_sock_wait_read(ctx->conn.socket) < 0) {
                // timed out
                break;
            }
        }
    }

    trilogy_free(&ctx->conn);

    return Qnil;
}

static VALUE rb_trilogy_last_insert_id(VALUE self) { return ULL2NUM(get_open_ctx(self)->conn.last_insert_id); }

static VALUE rb_trilogy_affected_rows(VALUE self) { return ULL2NUM(get_open_ctx(self)->conn.affected_rows); }

static VALUE rb_trilogy_warning_count(VALUE self) { return UINT2NUM(get_open_ctx(self)->conn.warning_count); }

static VALUE rb_trilogy_last_gtid(VALUE self)
{
    struct trilogy_ctx *ctx = get_open_ctx(self);
    if (ctx->conn.last_gtid_len > 0) {
        return rb_str_new(ctx->conn.last_gtid, ctx->conn.last_gtid_len);
    } else {
        return Qnil;
    }
}

static VALUE rb_trilogy_query_flags(VALUE self) { return UINT2NUM(get_ctx(self)->query_flags); }

static VALUE rb_trilogy_query_flags_set(VALUE self, VALUE query_flags)
{
    return get_ctx(self)->query_flags = NUM2UINT(query_flags);
}

static VALUE rb_trilogy_server_status(VALUE self) { return LONG2FIX(get_open_ctx(self)->conn.server_status); }

static VALUE rb_trilogy_server_version(VALUE self) { return rb_str_new_cstr(get_open_ctx(self)->server_version); }

void Init_cext()
{
    VALUE Trilogy = rb_define_class("Trilogy", rb_cObject);

    rb_define_alloc_func(Trilogy, allocate_trilogy);

    rb_define_method(Trilogy, "initialize", rb_trilogy_initialize, 1);
    rb_define_method(Trilogy, "change_db", rb_trilogy_change_db, 1);
    rb_define_method(Trilogy, "query", rb_trilogy_query, 1);
    rb_define_method(Trilogy, "ping", rb_trilogy_ping, 0);
    rb_define_method(Trilogy, "escape", rb_trilogy_escape, 1);
    rb_define_method(Trilogy, "close", rb_trilogy_close, 0);
    rb_define_method(Trilogy, "last_insert_id", rb_trilogy_last_insert_id, 0);
    rb_define_method(Trilogy, "affected_rows", rb_trilogy_affected_rows, 0);
    rb_define_method(Trilogy, "warning_count", rb_trilogy_warning_count, 0);
    rb_define_method(Trilogy, "last_gtid", rb_trilogy_last_gtid, 0);
    rb_define_method(Trilogy, "query_flags", rb_trilogy_query_flags, 0);
    rb_define_method(Trilogy, "query_flags=", rb_trilogy_query_flags_set, 1);
    rb_define_method(Trilogy, "server_status", rb_trilogy_server_status, 0);
    rb_define_method(Trilogy, "server_version", rb_trilogy_server_version, 0);
    rb_define_const(Trilogy, "TLS_VERSION_10", INT2NUM(TRILOGY_TLS_VERSION_10));
    rb_define_const(Trilogy, "TLS_VERSION_11", INT2NUM(TRILOGY_TLS_VERSION_11));
    rb_define_const(Trilogy, "TLS_VERSION_12", INT2NUM(TRILOGY_TLS_VERSION_12));
    rb_define_const(Trilogy, "TLS_VERSION_13", INT2NUM(TRILOGY_TLS_VERSION_13));

    rb_define_const(Trilogy, "SSL_DISABLED", INT2NUM(TRILOGY_SSL_DISABLED));
    rb_define_const(Trilogy, "SSL_VERIFY_IDENTITY", INT2NUM(TRILOGY_SSL_VERIFY_IDENTITY));
    rb_define_const(Trilogy, "SSL_VERIFY_CA", INT2NUM(TRILOGY_SSL_VERIFY_CA));
    rb_define_const(Trilogy, "SSL_REQUIRED_NOVERIFY", INT2NUM(TRILOGY_SSL_REQUIRED_NOVERIFY));
    rb_define_const(Trilogy, "SSL_PREFERRED_NOVERIFY", INT2NUM(TRILOGY_SSL_PREFERRED_NOVERIFY));

    rb_define_const(Trilogy, "QUERY_FLAGS_NONE", INT2NUM(0));
    rb_define_const(Trilogy, "QUERY_FLAGS_CAST", INT2NUM(TRILOGY_FLAGS_CAST));
    rb_define_const(Trilogy, "QUERY_FLAGS_CAST_BOOLEANS", INT2NUM(TRILOGY_FLAGS_CAST_BOOLEANS));
    rb_define_const(Trilogy, "QUERY_FLAGS_LOCAL_TIMEZONE", INT2NUM(TRILOGY_FLAGS_LOCAL_TIMEZONE));
    rb_define_const(Trilogy, "QUERY_FLAGS_FLATTEN_ROWS", INT2NUM(TRILOGY_FLAGS_FLATTEN_ROWS));
    rb_define_const(Trilogy, "QUERY_FLAGS_DEFAULT", INT2NUM(TRILOGY_FLAGS_DEFAULT));

    rb_cTrilogyError = rb_define_class_under(Trilogy, "Error", rb_eStandardError);
    rb_global_variable(&rb_cTrilogyError);

    Trilogy_DatabaseError = rb_define_class_under(Trilogy, "DatabaseError", rb_cTrilogyError);
    rb_global_variable(&Trilogy_DatabaseError);

    rb_define_attr(Trilogy_DatabaseError, "error_code", 1, 0);
    rb_define_attr(Trilogy_DatabaseError, "error_message", 1, 0);

    Trilogy_Result = rb_define_class_under(Trilogy, "Result", rb_cObject);
    rb_global_variable(&Trilogy_Result);

    rb_define_attr(Trilogy_Result, "affected_rows", 1, 0);
    rb_define_attr(Trilogy_Result, "fields", 1, 0);
    rb_define_attr(Trilogy_Result, "last_insert_id", 1, 0);
    rb_define_attr(Trilogy_Result, "rows", 1, 0);
    rb_define_attr(Trilogy_Result, "query_time", 1, 0);

    id_socket = rb_intern("socket");
    id_host = rb_intern("host");
    id_port = rb_intern("port");
    id_username = rb_intern("username");
    id_password = rb_intern("password");
    id_found_rows = rb_intern("found_rows");
    id_connect_timeout = rb_intern("connect_timeout");
    id_read_timeout = rb_intern("read_timeout");
    id_write_timeout = rb_intern("write_timeout");
    id_keepalive_enabled = rb_intern("keepalive_enabled");
    id_keepalive_idle = rb_intern("keepalive_idle");
    id_keepalive_count = rb_intern("keepalive_count");
    id_keepalive_interval = rb_intern("keepalive_interval");
    id_database = rb_intern("database");
    id_ssl_ca = rb_intern("ssl_ca");
    id_ssl_capath = rb_intern("ssl_capath");
    id_ssl_cert = rb_intern("ssl_cert");
    id_ssl_cipher = rb_intern("ssl_cipher");
    id_ssl_crl = rb_intern("ssl_crl");
    id_ssl_crlpath = rb_intern("ssl_crlpath");
    id_ssl_key = rb_intern("ssl_key");
    id_ssl_mode = rb_intern("ssl_mode");
    id_tls_ciphersuites = rb_intern("tls_ciphersuites");
    id_tls_min_version = rb_intern("tls_min_version");
    id_tls_max_version = rb_intern("tls_max_version");

    id_ivar_affected_rows = rb_intern("@affected_rows");
    id_ivar_fields = rb_intern("@fields");
    id_ivar_last_insert_id = rb_intern("@last_insert_id");
    id_ivar_rows = rb_intern("@rows");
    id_ivar_query_time = rb_intern("@query_time");

    rb_trilogy_cast_init();

// server_status flags
#define XX(name, code) rb_const_set(Trilogy, rb_intern((char *)#name + strlen("TRILOGY_")), LONG2NUM(name));
    TRILOGY_SERVER_STATUS(XX)
#undef XX
}
