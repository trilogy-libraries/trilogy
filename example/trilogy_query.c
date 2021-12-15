#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trilogy.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 3306
#define DEFAULT_USER "nobody"

static int execute_query(trilogy_conn_t *conn, const char *sql)
{
    fprintf(stderr, "\nsending query command\n");

    uint64_t column_count = 0;

    int rc = trilogy_query(conn, sql, strlen(sql), &column_count);

    switch (rc) {
    case TRILOGY_OK:
        fprintf(stderr, "(no results)\n");
        return rc;

    case TRILOGY_HAVE_RESULTS:
        break;

    default:
        return rc;
    }

    bool *binary_columns = calloc(column_count, sizeof(bool));

    for (uint64_t i = 0; i < column_count; i++) {
        trilogy_column_packet_t column;

        rc = trilogy_read_full_column(conn, &column);

        if (rc < 0) {
            free(binary_columns);
            return rc;
        }

        printf("%.*s", (int)column.name_len, column.name);

        if (i + 1 < column_count) {
            printf(",");
        }

        binary_columns[i] = false;
        if (column.flags & TRILOGY_COLUMN_FLAG_BINARY) {
            binary_columns[i] = true;
        }
    }

    printf("\n");

    // shut scan-build up
    if (column_count == 0) {
        free(binary_columns);
        return TRILOGY_OK;
    }

    trilogy_value_t *values = calloc(column_count, sizeof(trilogy_value_t));

    while ((rc = trilogy_read_full_row(conn, values)) == TRILOGY_OK) {
        for (uint64_t i = 0; i < column_count; i++) {
            if (values[i].is_null) {
                printf("NULL");
            } else {
                if (binary_columns[i]) {
                    printf("\"<<<binary value - %zu bytes>>>\"", values[i].data_len);
                } else {
                    printf("\"%.*s\"", (int)values[i].data_len, (const char *)values[i].data);
                }
            }

            if (i + 1 < column_count) {
                printf(",");
            }
        }

        printf("\n");
    }

    free(binary_columns);
    free(values);

    if (rc == TRILOGY_EOF) {
        rc = TRILOGY_OK;
    }

    return rc;
}

void fail_on_error(const trilogy_conn_t *conn, int err, const char *description)
{
    if (err < 0) {
        fprintf(stderr, "%s error: %s %d\n", description, trilogy_error(err), err);
        if (err == TRILOGY_ERR) {
            fprintf(stderr, "%d %.*s\n", conn->error_code, (int)conn->error_message_len, conn->error_message);
        } else if (err == TRILOGY_SYSERR) {
            perror("");
        }
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    trilogy_sockopt_t connopt = {0};
    char *sql = NULL;

    static struct option longopts[] = {{"host", optional_argument, NULL, 'h'},
                                       {"port", optional_argument, NULL, 'P'},
                                       {"sql", optional_argument, NULL, 's'},
                                       {"database", optional_argument, NULL, 'd'},
                                       {"user", optional_argument, NULL, 'u'},
                                       {"pass", optional_argument, NULL, 'p'},
                                       {NULL, 0, NULL, 0}};

    if (!(connopt.hostname = getenv("MYSQL_HOST"))) {
        connopt.hostname = DEFAULT_HOST;
    }
    connopt.hostname = strdup(connopt.hostname);

    const char *port = getenv("MYSQL_TCP_PORT");

    if (port != NULL) {
        connopt.port = atoi(port);
    }

    if (connopt.port == 0) {
        connopt.port = DEFAULT_PORT;
    }

    if (!(connopt.username = getenv("USER"))) {
        connopt.username = DEFAULT_USER;
    }
    connopt.username = strdup(connopt.username);

    int opt = 0;
    while ((opt = getopt_long(argc, argv, "h:P:s:d:u:p:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            if (optarg) {
                free(connopt.hostname);
                connopt.hostname = strdup(optarg);
            }
            break;
        case 'P':
            if (optarg) {
                connopt.port = atoi(optarg);
            }
            break;
        case 's':
            if (optarg) {
                free(sql);
                sql = strdup(optarg);
            }
            break;
        case 'd':
            if (optarg) {
                free(connopt.database);
                connopt.database = strdup(optarg);
            }
            break;
        case 'u':
            if (optarg) {
                free(connopt.username);
                connopt.username = strdup(optarg);
            }
            break;
        case 'p':
            if (optarg) {
                free(connopt.password);
                connopt.password = strdup(optarg);
                connopt.password_len = strlen(optarg);
            }
            break;
        }
    }

    int err;

    trilogy_conn_t conn;
    trilogy_init(&conn);

    fprintf(stderr, "connecting to %s:%hu as %s...\n", connopt.hostname, connopt.port, connopt.username);
    err = trilogy_connect(&conn, &connopt);
    fail_on_error(&conn, err, "connect");
    fprintf(stderr, "connected\n");

    fprintf(stderr, "\nsending ping command\n");
    err = trilogy_ping(&conn);
    fail_on_error(&conn, err, "ping");
    fprintf(stderr, "ping success\n");

    if (connopt.database) {
        fprintf(stderr, "\nsending change db command\n");
        err = trilogy_change_db(&conn, connopt.database, strlen(connopt.database));
        fail_on_error(&conn, err, "change db");
        fprintf(stderr, "change db success\n");
    }

    if (sql) {
        switch ((err = execute_query(&conn, sql))) {
        case TRILOGY_OK:
            break;

        case TRILOGY_ERR:
            fprintf(stderr, "error executing query: mysql said: %d %.*s\n", conn.error_code,
                    (int)conn.error_message_len, conn.error_message);
            break;

        default:
            fail_on_error(&conn, err, "executing query");
        }
    }

    fprintf(stderr, "\nsending quit command and closing connection\n");
    err = trilogy_close(&conn);
    fail_on_error(&conn, err, "closing connection");
    fprintf(stderr, "connection closed\n");

    free(connopt.hostname);
    free(connopt.username);
    free(sql);
    free(connopt.database);
    free(connopt.password);

    trilogy_free(&conn);
    exit(EXIT_SUCCESS);
}
