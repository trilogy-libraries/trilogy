#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test.h"

#include "trilogy/blocking.h"
#include "trilogy/client.h"
#include "trilogy/error.h"

static trilogy_sockopt_t caching_sha2_no_tls_options(void)
{
    trilogy_sockopt_t opts = *get_connopt();
    opts.username = "caching_sha2";
    opts.password = "password";
    opts.password_len = strlen(opts.password);
    opts.ssl_mode = TRILOGY_SSL_DISABLED;
    opts.flags &= (TRILOGY_CAPABILITIES_t)~TRILOGY_CAPABILITIES_SSL;

    return opts;
}

// Check if server supports caching_sha2_password
// - MySQL 8+ supports it
// - MariaDB 12.1+ supports it (Community Server)
// Returns 1 if supported, 0 otherwise
static int has_caching_sha2_support(void)
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    int err = trilogy_init(&conn);
    if (err != TRILOGY_OK) return 0;

    err = trilogy_connect_send(&conn, get_connopt());
    if (err != TRILOGY_OK) {
        trilogy_free(&conn);
        return 0;
    }

    err = trilogy_connect_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = trilogy_sock_wait_read(conn.socket);
        if (err != TRILOGY_OK) {
            trilogy_free(&conn);
            return 0;
        }
        err = trilogy_connect_recv(&conn, &handshake);
    }
    if (err != TRILOGY_OK) {
        trilogy_free(&conn);
        return 0;
    }

    const char *version = handshake.server_version;
    int supported = 0;

    // Check for MariaDB (version string contains "MariaDB")
    if (strstr(version, "MariaDB") != NULL || strstr(version, "mariadb") != NULL) {
        // MariaDB version format: "10.6.18-MariaDB" or "11.4.5-MariaDB"
        // caching_sha2_password only available in MariaDB 12.1+
        int major = atoi(version);
        supported = (major >= 12);
    } else {
        // MySQL version format: "8.0.36" or "9.5.0"
        // caching_sha2_password available in MySQL 8+
        int major = atoi(version);
        supported = (major >= 8);
    }

    trilogy_free(&conn);
    return supported;
}

#define do_connect(CONN, HANDSHAKE)                                                                                    \
    do {                                                                                                               \
        int err = trilogy_init(CONN);                                                                                  \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect_send(CONN, get_connopt());                                                               \
        ASSERT_OK(err);                                                                                                \
        err = trilogy_connect_recv(CONN, HANDSHAKE);                                                                   \
        while (err == TRILOGY_AGAIN) {                                                                                 \
            err = wait_readable(CONN);                                                                                 \
            ASSERT_OK(err);                                                                                            \
            err = trilogy_connect_recv(CONN, HANDSHAKE);                                                               \
        }                                                                                                              \
        ASSERT_OK(err);                                                                                                \
    } while (0);

TEST test_auth_send()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_send_closed_socket()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);
    close_socket(&conn);

    int err = trilogy_auth_send(&conn, &handshake);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_recv()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    err = trilogy_auth_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);

        err = trilogy_auth_recv(&conn, &handshake);
    }
    if (err == TRILOGY_AUTH_SWITCH) {
        err = trilogy_auth_switch_send(&conn, &handshake);

        while (err == TRILOGY_AGAIN) {
            err = wait_readable(&conn);
            ASSERT_OK(err);

            err = trilogy_auth_recv(&conn, &handshake);
        }
    }
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_recv_closed_socket()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    do_connect(&conn, &handshake);

    int err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);

        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);

    close_socket(&conn);

    err = trilogy_auth_recv(&conn, &handshake);
    ASSERT_ERR(TRILOGY_SYSERR, err);

    trilogy_free(&conn);
    PASS();
}

TEST test_ssl_handshake()
{
    trilogy_conn_t conn;
    trilogy_handshake_t handshake;

    if (getenv("MYSQL_SSL") == NULL)
        SKIP();

    do_connect(&conn, &handshake);
    int err = trilogy_ssl_request_send(&conn);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);
        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);
    err = trilogy_sock_upgrade_ssl(conn.socket);
    ASSERT_OK(err);
    err = trilogy_auth_send(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_writable(&conn);
        ASSERT_OK(err);
        err = trilogy_flush_writes(&conn);
    }
    ASSERT_OK(err);
    err = trilogy_auth_recv(&conn, &handshake);
    while (err == TRILOGY_AGAIN) {
        err = wait_readable(&conn);
        ASSERT_OK(err);
        err = trilogy_auth_recv(&conn, &handshake);
    }
    if (err == TRILOGY_AUTH_SWITCH) {
        err = trilogy_auth_switch_send(&conn, &handshake);

        while (err == TRILOGY_AGAIN) {
            err = wait_readable(&conn);
            ASSERT_OK(err);

            err = trilogy_auth_recv(&conn, &handshake);
        }
    }
    ASSERT_OK(err);
    trilogy_free(&conn);
    PASS();
}

TEST test_auth_caching_sha2_tcp_no_tls()
{
    if (!has_caching_sha2_support())
        SKIPm("caching_sha2_password not supported on this server");

    trilogy_conn_t conn;

    trilogy_sockopt_t opts = caching_sha2_no_tls_options();

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    err = trilogy_connect(&conn, &opts);
    ASSERT_OK(err);

    err = trilogy_close(&conn);
    ASSERT_OK(err);

    trilogy_free(&conn);
    PASS();
}

TEST test_auth_caching_sha2_tcp_no_tls_wrong_password()
{
    if (!has_caching_sha2_support())
        SKIPm("caching_sha2_password not supported on this server");

    trilogy_conn_t conn;

    trilogy_sockopt_t opts = caching_sha2_no_tls_options();
    opts.password = "wrong";
    opts.password_len = strlen(opts.password);

    int err = trilogy_init(&conn);
    ASSERT_OK(err);

    err = trilogy_connect(&conn, &opts);
    ASSERT_ERR(TRILOGY_ERR, err);

    trilogy_free(&conn);
    PASS();
}

int client_auth_test()
{
    RUN_TEST(test_auth_send);
    RUN_TEST(test_auth_send_closed_socket);
    RUN_TEST(test_auth_recv);
    RUN_TEST(test_auth_recv_closed_socket);
    RUN_TEST(test_ssl_handshake);
    RUN_TEST(test_auth_caching_sha2_tcp_no_tls);
    RUN_TEST(test_auth_caching_sha2_tcp_no_tls_wrong_password);

    return 0;
}
