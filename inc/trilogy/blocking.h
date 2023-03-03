#ifndef TRILOGY_BLOCKING_H
#define TRILOGY_BLOCKING_H

#include "client.h"

/* Trilogy Blocking Client API
 *
 * This API is a set of high level functions for issuing commands to the MySQL-compatible
 * server. Being just a simple wrapper around the non-blocking API - each call
 * will block until a full request and response cycle has completed, or an error
 * occurs.
 *
 * The trilogy_init function from client.h should be used to initialize a
 * trilogy_conn_t struct. While trilogy_free should be used to ensure any internal
 * buffers are freed.
 *
 * Applications requiring finer-grained control over I/O should use the
 * non-blocking API in client.h
 */

/* trilogy_connect - Establish a connection to a MySQL-compatible server
 *
 * conn     - A pre-initialized trilogy_conn_t pointer.
 * opts     - Connection options for where to connect to.
 *
 * Return values
 *   TRILOGY_OK                 - Connected and authenticated successfully.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection was severed during
 * authentication. TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing
 * a network packet.
 */
int trilogy_connect(trilogy_conn_t *conn, const trilogy_sockopt_t *opts);

/* trilogy_connect_sock - Establish a connection to a MySQL-compatible server with an
 *                    - existing socket.
 *
 * conn     - A pre-initialized trilogy_conn_t pointer.
 * sock     - A  connected socket.
 *
 * Return values
 *   TRILOGY_OK                 - Connected and authenticated successfully.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection was severed during
 * authentication. TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing
 * a network packet.
 */
int trilogy_connect_sock(trilogy_conn_t *conn, trilogy_sock_t *sock);

/* trilogy_change_db - Change the default database for a connection.
 *
 * conn     - A connected trilogy_conn_t pointer. Using a disconnected
 *            trilogy_conn_t is undefined.
 * name     - Name of the database to set as default.
 * name_len - Length of the database name string in bytes.
 *
 * Return values
 *   TRILOGY_OK                 - The change db command completed successfully.
 *   TRILOGY_ERR                - The server returned an error.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_change_db(trilogy_conn_t *conn, const char *name, size_t name_len);

/* trilogy_query - Send and execute a query.
 *
 * conn             - A connected trilogy_conn_t pointer. Using a disconnected
 *                    trilogy_conn_t is undefined.
 * query            - The query string to be sent to the server.
 * query_len        - Length of the query string in bytes.
 * column_count_out - Out parameter; The number of columns in the result set.
 *
 * Return values
 *   TRILOGY_OK                 - The query completed successfully and there are
 * no results to be read. TRILOGY_HAVE_RESULTS       - The query completed
 * successfully and there are results to be read. The caller must then call
 *                             trilogy_read_full_column to read all column info
 *                             packets, then trilogy_read_full_row until all rows
 *                             have been read.
 *   TRILOGY_ERR                - The server returned an error.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_query(trilogy_conn_t *conn, const char *query, size_t query_len, uint64_t *column_count_out);

/* trilogy_read_full_column - Read a column from the result set.
 *
 * This should be called after issuing a query that has results. For example:
 * an INSERT query won't have a result set.
 *
 * Calling this function at any other time during the connection lifecycle is
 * undefined.
 *
 * conn       - A connected trilogy_conn_t pointer. Using a disconnected
 *              trilogy_conn_t is undefined.
 * column_out - Out parameter; A pointer to a pre-allocated trilogy_column_t,
 * which will be filled out by this function.
 *
 * Return values
 *   TRILOGY_OK                 - The column was successfully read.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_read_full_column(trilogy_conn_t *conn, trilogy_column_t *column_out);

/* trilogy_read_full_row - Read a row from the result set.
 *
 * This should only be called after reading all of the columns from a result
 * set.
 *
 * Calling this function at any other time during the connection lifecycle is
 * undefined.
 *
 * conn       - A connected trilogy_conn_t pointer. Using a disconnected
 *              trilogy_conn_t is undefined.
 * values_out - Out parameter; A pointer to a pre-allocated trilogy_value_t, which
 *              will be filled out by this function. It should be allocated with
 *              enough space to hold a trilogy_value_t pointer for each column.
 *              Something like: `(sizeof(trilogy_value_t) * column_count)`.
 *
 * Return values
 *   TRILOGY_OK                 - The row was successfully read.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_read_full_row(trilogy_conn_t *conn, trilogy_value_t *values_out);

/* trilogy_ping - Send a ping command to the server.
 *
 * conn - A connected trilogy_conn_t pointer. Using a disconnected trilogy_conn_t
 *        is undefined.
 *
 * Return values
 *   TRILOGY_OK                 - The ping command completed successfully.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_ping(trilogy_conn_t *conn);

/* trilogy_close - Send a quit command to the server.
 *
 * conn - A connected trilogy_conn_t pointer. Using a disconnected trilogy_conn_t
 *        is undefined.
 *
 * Return values
 *   TRILOGY_OK                 - The quit command was completed successfully.
 *   TRILOGY_SYSERR             - A system error occurred, check errno.
 *   TRILOGY_CLOSED_CONNECTION  - The connection is closed.
 *   TRILOGY_PROTOCOL_VIOLATION - An error occurred while processing a network
 *                             packet.
 */
int trilogy_close(trilogy_conn_t *conn);

#endif
