#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "trilogy.h"

// TODO@vmg: use a custom socket for fuzzing

#if 0
static void read_columns(trilogy_conn_t *conn, uint64_t column_count) {
	for (uint64_t i = 0; i < column_count; i++) {
		trilogy_column_packet_t column;
		if (trilogy_read_full_column(conn, &column) != TRILOGY_OK)
			return;
	}

	trilogy_value_t *values = calloc(column_count, sizeof(trilogy_value_t));
	if (values) {
		while (trilogy_read_full_row(conn, values) == TRILOGY_OK) {
		}

		free(values);
	}
}

#define SQL_LEN (32)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	/* Use the first SQL_LEN bytes as a sql statement, then
	 * the remainder is used as data from the server */
	if (size < SQL_LEN)
		return 0;

	const char *sql = (const char *)data;
	data += SQL_LEN;
	size -= SQL_LEN;

	/* "Store" the remainder of the data in a socketpair,
	 * which trilogy can then read from */
	int socket_fds[2];
	int res = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds);
	if (res < 0)
		return 0;
	ssize_t send_res = send(socket_fds[1], data, size, 0);
	if (send_res != (ssize_t)size)
		return 0;
	res = shutdown(socket_fds[1], SHUT_WR);
	if (res != 0)
		return 0;

	trilogy_conn_t conn;
	trilogy_init(&conn);

	const char *user = "username";
	const char *password = "password";
	const char *db = "database";

	if (trilogy_connect_fd(&conn, socket_fds[0], user, password, strlen(password), 0) == TRILOGY_OK) {
		if (trilogy_ping(&conn) == TRILOGY_OK) {
			if (trilogy_change_db(&conn, db, strlen(db)) == TRILOGY_OK) {
				const char *escaped_sql = NULL;
				size_t escaped_sql_len = 0;

				if (trilogy_escape(&conn, sql, SQL_LEN, &escaped_sql, &escaped_sql_len) == TRILOGY_OK) {
					uint64_t column_count = 0;

					while (trilogy_query(&conn, sql, strlen(sql), &column_count) == TRILOGY_HAVE_RESULTS) {
						if (column_count) {
							read_columns(&conn, column_count);
						}
					}
				}
			}
		}
		trilogy_close(&conn);
	}

	trilogy_free(&conn);
	close(socket_fds[0]);
	close(socket_fds[1]);
	return 0;
}
#endif
