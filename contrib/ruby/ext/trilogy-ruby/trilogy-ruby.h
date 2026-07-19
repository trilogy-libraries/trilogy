#ifndef TRILOGY_RUBY_H
#define TRILOGY_RUBY_H

#include <ruby.h>
#include <ruby/ractor.h>
#include <trilogy_xallocator.h>
#include <trilogy.h>

#include <stdbool.h>

#define TRILOGY_FLAGS_CAST 1
#define TRILOGY_FLAGS_CAST_BOOLEANS 2
#define TRILOGY_FLAGS_LOCAL_TIMEZONE 4
#define TRILOGY_FLAGS_FLATTEN_ROWS 8
#define TRILOGY_FLAGS_CAST_ALL_DECIMALS_TO_BIGDECIMALS 16
#define TRILOGY_FLAGS_CAST_SHAREABLE 32
#define TRILOGY_FLAGS_DEFAULT (TRILOGY_FLAGS_CAST)

struct rb_trilogy_cast_options {
    bool cast;
    bool cast_booleans;
    bool database_local_time;
    bool flatten_rows;
    bool cast_decimals_to_bigdecimals;
    bool shareable;
};

struct column_info {
    TRILOGY_TYPE_t type;
    TRILOGY_CHARSET_t charset;
    uint32_t len;
    uint16_t flags;
    uint8_t decimals;
};

extern VALUE Trilogy_CastError;

static inline VALUE rb_trilogy_shareable(VALUE obj, const struct rb_trilogy_cast_options *cast_options)
{
    if (cast_options->shareable) {
        RB_OBJ_SET_FROZEN_SHAREABLE(obj);
        // OBJ_FREEZE(obj);
// #ifdef RB_OBJ_SET_SHAREABLE
//         VALUE rb_obj_set_shareable(VALUE);
//         rb_obj_set_shareable(obj);
// #endif
    }
    return obj;
}

VALUE
rb_trilogy_cast_value(const trilogy_value_t *value, const struct column_info *column,
                      const struct rb_trilogy_cast_options *options);

void rb_trilogy_cast_init(void);

#endif
