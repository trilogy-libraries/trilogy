#ifndef TEST_H
#define TEST_H

#include "greatest.h"
#include "trilogy.h"
#include <stdbool.h>
#include <stdio.h>

#define ASSERT_ERR(EXP, GOT) ASSERT_ENUM_EQ((EXP), (GOT), trilogy_error)
#define ASSERT_OK(GOT) ASSERT_ERR(TRILOGY_OK, (GOT))
#define ASSERT_EOF(GOT) ASSERT_ERR(TRILOGY_EOF, (GOT))

/* Helpers */

const trilogy_sockopt_t *get_connopt();
int wait_readable(trilogy_conn_t *conn);
int wait_writable(trilogy_conn_t *conn);
void close_socket(trilogy_conn_t *conn);

#endif
