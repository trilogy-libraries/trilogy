#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"

int wait_readable(trilogy_conn_t *conn) { return trilogy_sock_wait_read(conn->socket); }

int wait_writable(trilogy_conn_t *conn) { return trilogy_sock_wait_write(conn->socket); }

void close_socket(trilogy_conn_t *conn) { close(trilogy_sock_fd(conn->socket)); }
