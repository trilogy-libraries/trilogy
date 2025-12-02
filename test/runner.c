#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

GREATEST_MAIN_DEFS();

typedef int (*trilogy_test_t)();

static trilogy_sockopt_t connopt;

const trilogy_sockopt_t *get_connopt(void) { return &connopt; }

#define ALL_SUITES(SUITE)                                                                                              \
    SUITE(reader_test)                                                                                                 \
    SUITE(buffer_test)                                                                                                 \
    SUITE(builder_test)                                                                                                \
    SUITE(error_test)                                                                                                  \
    SUITE(packet_parser_test)                                                                                          \
    SUITE(charset_test)                                                                                                \
    SUITE(binlog_test)                                                                                                 \
    SUITE(blocking_test)                                                                                               \
    SUITE(socket_test)                                                                                                 \
    SUITE(parse_handshake_test)                                                                                        \
    SUITE(parse_ok_packet_test)                                                                                        \
    SUITE(parse_eof_packet_test)                                                                                       \
    SUITE(parse_result_packet_test)                                                                                    \
    SUITE(parse_error_packet_test)                                                                                     \
    SUITE(parse_column_packet_test)                                                                                    \
    SUITE(parse_row_packet_test)                                                                                       \
    SUITE(build_auth_packet_test)                                                                                      \
    SUITE(build_change_db_packet_test)                                                                                 \
    SUITE(build_ping_packet_test)                                                                                      \
    SUITE(build_quit_packet_test)                                                                                      \
    SUITE(build_set_option_packet_test)                                                                                \
    SUITE(build_query_packet_test)                                                                                     \
    SUITE(stmt_prepare_packet_test)                                                                                    \
    SUITE(stmt_bind_data_packet_test)                                                                                  \
    SUITE(stmt_execute_packet_test)                                                                                    \
    SUITE(stmt_reset_packet_test)                                                                                      \
    SUITE(stmt_close_packet_test)                                                                                      \
    SUITE(client_connect_test)                                                                                         \
    SUITE(client_escape_test)                                                                                          \
    SUITE(client_auth_test)                                                                                            \
    SUITE(client_change_db_test)                                                                                       \
    SUITE(client_set_option_test)                                                                                      \
    SUITE(client_ping_test)                                                                                            \
    SUITE(client_stmt_prepare_test)                                                                                    \
    SUITE(client_stmt_execute_test)                                                                                    \
    SUITE(client_stmt_reset_test)                                                                                      \
    SUITE(client_stmt_close_test)                                                                                      \

#define XX(name) extern int name();
ALL_SUITES(XX)
#undef XX

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();

    connopt.hostname = getenv("MYSQL_HOST");
    if (connopt.hostname == NULL) {
        connopt.hostname = "127.0.0.1";
    }

    const char *port = getenv("MYSQL_PORT");
    if (port != NULL) {
        connopt.port = atoi(port);
    }

    if (connopt.port == 0) {
        connopt.port = 3306;
    }

    connopt.username = getenv("MYSQL_USER");
    if (connopt.username == NULL) {
        connopt.username = "root";
    }

    connopt.password = getenv("MYSQL_PASS");
    if (connopt.password != NULL) {
        connopt.password_len = strlen(connopt.password);
    }

    connopt.database = getenv("MYSQL_DB");
    if (connopt.database == NULL) {
        connopt.database = "test";
    }

#define XX(name) name();
    ALL_SUITES(XX)
#undef XX

    GREATEST_MAIN_END();
}
