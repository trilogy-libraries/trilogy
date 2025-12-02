#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trilogy.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 3306
#define DEFAULT_USER "nobody"
#define DEFAULT_BINLOGF "binlog.000005"


enum {
    FORMAT_DESCRIPTION_EVENT = 15,
    TABLE_MAP_EVENT = 19,
    WRITE_ROWS_EVENT = 30,
};
enum enum_field_types {
    MYSQL_TYPE_DECIMAL = 0,
    MYSQL_TYPE_TINY,
    MYSQL_TYPE_SHORT,
    MYSQL_TYPE_LONG,
    MYSQL_TYPE_FLOAT,
    MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_NULL,
    MYSQL_TYPE_TIMESTAMP,
    MYSQL_TYPE_LONGLONG,
    MYSQL_TYPE_INT24,
    MYSQL_TYPE_DATE,
    MYSQL_TYPE_TIME,
    MYSQL_TYPE_DATETIME,
    MYSQL_TYPE_YEAR,
    MYSQL_TYPE_NEWDATE, /**< Internal to MySQL. Not used in protocol */
    MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_TIMESTAMP2,
    MYSQL_TYPE_DATETIME2,   /**< Internal to MySQL. Not used in protocol */
    MYSQL_TYPE_TIME2,       /**< Internal to MySQL. Not used in protocol */
    MYSQL_TYPE_TYPED_ARRAY, /**< Used for replication only */
    MYSQL_TYPE_INVALID = 243,
    MYSQL_TYPE_BOOL = 244, /**< Currently just a placeholder */
    MYSQL_TYPE_JSON = 245,
    MYSQL_TYPE_NEWDECIMAL = 246,
    MYSQL_TYPE_ENUM = 247,
    MYSQL_TYPE_SET = 248,
    MYSQL_TYPE_TINY_BLOB = 249,
    MYSQL_TYPE_MEDIUM_BLOB = 250,
    MYSQL_TYPE_LONG_BLOB = 251,
    MYSQL_TYPE_BLOB = 252,
    MYSQL_TYPE_VAR_STRING = 253,
    MYSQL_TYPE_STRING = 254,
    MYSQL_TYPE_GEOMETRY = 255
};

typedef struct binlog_format_description_event {
    uint16_t binlog_version;
    uint8_t server_version[50];
    uint32_t create_timestamp;
    uint8_t header_length;
    uint8_t* post_header_len;
} binlog_format_description_event_t;


typedef struct binlog_table_map_event {
    uint64_t table_id;
    uint16_t flags;
    uint64_t dbname_len;
    uint8_t* dbname;
    uint64_t tblname_len;
    uint8_t* tblname;
    uint64_t column_count;
    uint8_t* column_types;
} binlog_table_map_event_t;

typedef struct binlog_rows_event {
    uint64_t table_id;
    uint16_t flags;
    uint64_t width;
    uint8_t* cols;
    uint64_t cols_len;
    // not support, extra_row_info
    uint8_t* rows;
    uint64_t rows_len;
    uint64_t cols_bitmap_width;
    uint8_t* cols_bitmap;
    uint64_t cols_bitmap_len;
} binlog_rows_event_t;

static int quit = 0;

void sigint_handler(int signum)
{
    (void)signum;
    quit++;
}


uint64_t packed_int_incr_addr(uint8_t* data, uint32_t *offset)
{
    uint8_t fsb = *(data + (*offset));
    uint64_t packed_result = 0;
    if (fsb < 251) {
        packed_result = (uint64_t)fsb;
        (*offset) += 1;
    } else if (fsb == 251) {
        packed_result = 0;
        (*offset) += 1;
    } else if (fsb == 252) {
        memcpy(&packed_result, data + (*offset), 2 );
        (*offset) += 3;
    } else if (fsb == 253) {
        memcpy( &packed_result, data + (*offset), 3 );
        (*offset) += 4;
    } else {
        memcpy( &packed_result, data + (*offset), 8 );
        (*offset) += 9;
    }
    return packed_result;
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
    // Setup signal handler for Ctrl+C
    signal(SIGINT, sigint_handler);

    trilogy_conn_t conn;
    trilogy_sockopt_t connopt = {0};
    char *binlogf = NULL;
    int opt = 0;
    int err;

    const char *port = getenv("MYSQL_TCP_PORT");

    static struct option longopts[] = {{"host", optional_argument, NULL, 'h'},
                                       {"port", optional_argument, NULL, 'P'},
                                       {"binlogf", optional_argument, NULL, 'b'},
                                       {"database", optional_argument, NULL, 'd'},
                                       {"user", optional_argument, NULL, 'u'},
                                       {"pass", optional_argument, NULL, 'p'},
                                       {NULL, 0, NULL, 0}};

    if (!(connopt.hostname = getenv("MYSQL_HOST"))) {
        connopt.hostname = DEFAULT_HOST;
    }
    connopt.hostname = strdup(connopt.hostname);


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

    binlogf = strdup(DEFAULT_BINLOGF);

    while ((opt = getopt_long(argc, argv, "h:P:t:d:u:p:", longopts, NULL)) != -1) {
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
        case 'b':
            if (optarg) {
                free(binlogf);
                binlogf = strdup(optarg);
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

    const uint32_t binlogpos = 4;
    const size_t command_buffer_size = strlen(binlogf) + 4 + 2 + 4 + 1;
    uint8_t* command_buffer = (uint8_t*)malloc(command_buffer_size);
    uint8_t* ptr = command_buffer;
    uint32_t val32 = binlogpos;
    uint16_t val16 = 0;

    memcpy(ptr, &val32, sizeof(val32));
    ptr += sizeof(val32);
    memcpy(ptr, &val16, sizeof(val16));
    ptr += sizeof(val16);
    val32 = 71;
    memcpy(ptr, &val32, sizeof(val32));
    ptr += sizeof(val32);
    memcpy(ptr, binlogf, strlen(binlogf));

    if ((err = trilogy_binlog_dump(&conn, (const char*)command_buffer, command_buffer_size)) < 0) {
        fail_on_error(&conn, err, "trilogy_binlog_dump");
    }
    fprintf(stderr, "trilogy_binlog_dump success\n");


    binlog_format_description_event_t formatdesc_event;
    binlog_table_map_event_t table_map_event;
    binlog_rows_event_t rows_event;
    memset(&formatdesc_event, 0, sizeof(formatdesc_event));
    memset(&table_map_event, 0, sizeof(table_map_event));
    memset(&rows_event, 0, sizeof(rows_event));
    
    while(!quit) {
        trilogy_binlog_event_t binlog_event;
        uint32_t offset = 0;
        memset(&binlog_event, 0, sizeof(binlog_event));

        binlog_event.data_len = 64*1024;
        binlog_event.data = (uint8_t*)malloc(binlog_event.data_len);
        err = trilogy_binlog_dump_recv(&conn, &binlog_event);
        if (err == TRILOGY_EXTRA_DATA_IN_PACKET) {
            binlog_event.data_len = binlog_event.event_size;
            binlog_event.data = (uint8_t*)realloc(binlog_event.data, binlog_event.data_len);
            err = trilogy_binlog_dump_recv(&conn, &binlog_event);
        }
        if (err == TRILOGY_AGAIN) {
            usleep(10000);
            free(binlog_event.data);
            continue;
        }
        fail_on_error(&conn, err, "trilogy_binlog_dump_recv");
        fprintf(stderr, "trilogy_binlog_dump_recv success\n");

        
        switch(binlog_event.event_type) {
            case FORMAT_DESCRIPTION_EVENT: {
                offset = 0;
            /*
            +=====================================+
            | event  | binlog_version   19 : 2    | = 4
            | data   +----------------------------+
            |        | server_version   21 : 50   |
            |        +----------------------------+
            |        | create_timestamp 71 : 4    |
            |        +----------------------------+
            |        | header_length    75 : 1    |
            |        +----------------------------+
            |        | post-header      76 : n    | = array of n bytes, one byte
            |        | lengths for all            |   per event type that the
            |        | event types                |   server knows about
            +=====================================+
            */
                memcpy(
                    &formatdesc_event.binlog_version,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(formatdesc_event.binlog_version)
                );
                offset += sizeof(formatdesc_event.binlog_version);

                memcpy(
                    &formatdesc_event.server_version,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(formatdesc_event.server_version)
                );
                offset += sizeof(formatdesc_event.server_version);

                memcpy(
                    &formatdesc_event.create_timestamp,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(formatdesc_event.create_timestamp)
                );
                offset += sizeof(formatdesc_event.create_timestamp);

                memcpy(
                    &formatdesc_event.header_length,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(formatdesc_event.header_length)
                );
                offset += sizeof(formatdesc_event.header_length);

                formatdesc_event.post_header_len = (uint8_t*)malloc((binlog_event.event_size - 76));
                memcpy(
                    formatdesc_event.post_header_len,
                    ((uint8_t*)binlog_event.data) + offset,
                    (binlog_event.event_size - 76)
                );
                fprintf(stderr, "Format Description.(ver:%04x ,server:%s, event_size(-76):%4d, header_len:%02x, %02x)\n",
                    formatdesc_event.binlog_version,
                    formatdesc_event.server_version,
                    binlog_event.event_size - 76,
                    formatdesc_event.header_length,
                    formatdesc_event.post_header_len[TABLE_MAP_EVENT-1]
                );
            }   break;
            case TABLE_MAP_EVENT: {
            /*
            The buffer layout for fixed data part is as follows
            +------------------------------------+
            | table_id | reserved for future use |
            +------------------------------------+
            The buffer layout for variable data part is as follows
            +------------------------------------------------------------------+
            | var_header_len | column_before_image | columns_after_image | row |
            +------------------------------------------------------------------+
            +-------------------------------------------------------+
            | Event Type | Cols_before_image | Cols_after_image     |
            +-------------------------------------------------------+
            |  DELETE    |   Deleted row     |    NULL              |
            |  INSERT    |   NULL            |    Inserted row      | <-- support
            |  UPDATE    |   Old     row     |    Updated row       |
            +-------------------------------------------------------+
            */
                offset = 0;
                if (formatdesc_event.post_header_len == NULL) {
                    fail_on_error(&conn, TRILOGY_SYSERR, "FORMAT_DESCRIPTION_EVENT not received yet");
                }
                if (formatdesc_event.post_header_len[TABLE_MAP_EVENT-1] == 6) {
                    fail_on_error(&conn, TRILOGY_SYSERR, "not support(table id is 4 bytes)");
                }
                memcpy(
                    &table_map_event.table_id,
                    ((uint8_t*)binlog_event.data) + offset,
                    6
                );
                offset += 6;

                memcpy(
                    &table_map_event.flags,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(table_map_event.flags)
                );
                offset += sizeof(table_map_event.flags);
                table_map_event.dbname_len = packed_int_incr_addr(((uint8_t*)binlog_event.data), &offset);
                table_map_event.dbname = (uint8_t*)realloc(table_map_event.dbname, table_map_event.dbname_len);
                memcpy(
                    table_map_event.dbname,
                    ((uint8_t*)binlog_event.data) + offset,
                    table_map_event.dbname_len
                );
                offset += table_map_event.dbname_len + 1;

                table_map_event.tblname_len = packed_int_incr_addr(((uint8_t*)binlog_event.data), &offset);
                table_map_event.tblname = (uint8_t*)realloc(table_map_event.tblname, table_map_event.tblname_len);
                memcpy(
                    table_map_event.tblname,
                    ((uint8_t*)binlog_event.data) + offset,
                    table_map_event.tblname_len
                );
                offset += table_map_event.tblname_len + 1;

                table_map_event.column_count = packed_int_incr_addr(((uint8_t*)binlog_event.data), &offset);
                table_map_event.column_types = (uint8_t*)realloc(table_map_event.column_types, table_map_event.column_count);

                memcpy(
                    table_map_event.column_types,
                    ((uint8_t*)binlog_event.data) + offset,
                    table_map_event.column_count
                );
                offset += table_map_event.column_count;
            }   break;
            case WRITE_ROWS_EVENT: {
            /*
            The buffer layout for dynamic by data-types
            */
                offset = 0;
                if (formatdesc_event.post_header_len == NULL) {
                    fail_on_error(&conn, TRILOGY_SYSERR, "FORMAT_DESCRIPTION_EVENT not received yet");
                }
                if (formatdesc_event.post_header_len[TABLE_MAP_EVENT - 1] == 6) {
                    fail_on_error(&conn, TRILOGY_SYSERR, "not support(table id is 4 bytes)");
                }
                memcpy(
                    &rows_event.table_id,
                    ((uint8_t*)binlog_event.data) + offset,
                    6
                );
                offset += 6;

                memcpy(
                    &rows_event.flags,
                    ((uint8_t*)binlog_event.data) + offset,
                    sizeof(rows_event.flags)
                );
                offset += sizeof(rows_event.flags);
                // TODO: not support.ROWS_HEADER_LEN_V2(10)
                rows_event.width = packed_int_incr_addr(((uint8_t*)binlog_event.data), &offset);
                rows_event.cols_len = (uint64_t)((rows_event.width+7)/8);
                rows_event.cols = (uint8_t*)realloc(rows_event.cols, rows_event.cols_len);
                memcpy(
                    rows_event.cols,
                    ((uint8_t*)binlog_event.data) + offset,
                    rows_event.cols_len
                );
                offset += ((rows_event.width+7)/8);
                rows_event.rows_len = (uint64_t)((binlog_event.event_size - 19 - offset));
                rows_event.rows = (uint8_t*)realloc(rows_event.rows, rows_event.rows_len);
                memcpy(
                    rows_event.rows,
                    ((uint8_t*)binlog_event.data) + offset,
                    rows_event.rows_len
                );

                rows_event.cols_bitmap_width = packed_int_incr_addr(((uint8_t*)binlog_event.data), &offset);
                rows_event.cols_bitmap_len = (uint64_t)((rows_event.cols_bitmap_width+7)/8);
                rows_event.cols_bitmap = (uint8_t*)realloc(rows_event.cols_bitmap, rows_event.cols_bitmap_len);
                memcpy(
                    rows_event.cols_bitmap,
                    ((uint8_t*)binlog_event.data) + offset,
                    rows_event.cols_bitmap_len
                );

                offset += ((rows_event.cols_bitmap_width+7)/8);
                const uint8_t* value = rows_event.rows;
                value += ((rows_event.width+7)/8);
                value += ((rows_event.cols_bitmap_width+7)/8);

                for(;value < (rows_event.rows + rows_event.rows_len);) {
                    value += ((rows_event.cols_bitmap_width+7)/8);
                    for (size_t n = 0; n < table_map_event.column_count; n++) {
                        if ((rows_event.cols_bitmap[n/8] & (1<<(n&7))) == 0) {
                            continue;
                        }
                        const uint8_t typ = table_map_event.column_types[n];

                        switch(typ) {
                        case MYSQL_TYPE_LONGLONG: {
                            uint64_t v;
                            memcpy(&v, value, 8);
                            fprintf(stderr, "[%3d]%" PRIu64 ": %08x %08x\n", (int)n, (uint64_t)v, (uint32_t)(v & 0xFFFFFFFF), (uint32_t)((v >> 32) & 0xFFFFFFFF));
                            value += 8;
                        }   break;
                        case MYSQL_TYPE_YEAR:
                        case MYSQL_TYPE_TINY:
                            value += 1;
                            break;
                        case MYSQL_TYPE_SHORT:
                            value += 2;
                            break;
                        case MYSQL_TYPE_INT24:
                            value += 3;
                            break;
                        case MYSQL_TYPE_LONG:
                            value += 4;
                            break;
                        case MYSQL_TYPE_NULL:
                            value += 0;
                            break;
                        case MYSQL_TYPE_NEWDATE:
                            value += 3;
                            break;
                        case MYSQL_TYPE_DATE:
                        case MYSQL_TYPE_TIME:
                            value += 3;
                            break;
                        case MYSQL_TYPE_ENUM:
                        case MYSQL_TYPE_STRING:
                            value += 1;
                            break;
                        case MYSQL_TYPE_TIMESTAMP:
                        case MYSQL_TYPE_TIMESTAMP2:
                            value += (4 + 1 / 2);
                            break;
                        case MYSQL_TYPE_VARCHAR: {
                            int length = (int)(*value);
                            fprintf(stderr, "[%3d]%d: %.*s\n",(int) n, (int)length, (int)length, (const char*)(value + 1));
                            value += (length + 1);
                        }   break;
                        case MYSQL_TYPE_BLOB: {
                            uint16_t length;
                            memcpy(&length, value, sizeof(length));
                            fprintf(stderr, "[%3d]%d: %.*s\n", (int)n, (int)length, (int)length, (const char*)(value + 2));
                            value += (length + 2);
                        }   break;
                        case MYSQL_TYPE_DATETIME2: {
                            uint64_t v0 = (uint64_t)((uint32_t)value[4] +
                                ((uint32_t)value[3] << 8) +
                                ((uint32_t)value[2] << 16) +
                                ((uint32_t)value[1] << 24)) +
                                ((uint64_t)value[0] << 32);
                            v0 -= 0x8000000000LL;

                            uint64_t v1 = (uint64_t)((uint32_t)(value[6]) + ((uint32_t)(value[5]) << 8));
                            uint64_t ymdhms = (v0 >> 0);
                            uint64_t ymd = (ymdhms >> 17);
                            uint64_t ym = (ymd >> 5);
                            uint64_t hms = (ymdhms %(1<<17));
                            uint32_t day = ymd % (1<<5);
                            uint32_t month = (ym % 13);
                            uint32_t year = (ym / 13);
                            uint32_t second = hms % (1<<6);
                            uint32_t minute = (hms >> 6) % (1<<6);
                            uint32_t hour = (hms >> 12);
                            fprintf(stderr, "[%3d]%04u-%02u-%02u %02u:%02u:%02u.%03u\n", (int)n, year, month, day, hour, minute, second, (uint32_t)v1);
                            value += 7;
                        }   break;
                        }
                    }
                }
            }
            break;
        }
        free(binlog_event.data);
    }

    fprintf(stderr, "\nsending quit command and closing connection\n");
    err = trilogy_close(&conn);
    fail_on_error(&conn, err, "closing connection");
    fprintf(stderr, "connection closed\n");

    free(connopt.hostname);
    free(connopt.username);
    free(binlogf);
    free(connopt.database);
    free(connopt.password);

    trilogy_free(&conn);

    free(command_buffer);

    exit(EXIT_SUCCESS);
}
