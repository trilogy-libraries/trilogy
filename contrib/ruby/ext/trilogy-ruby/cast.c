#include <ruby.h>
#include <ruby/encoding.h>

#include <trilogy.h>

#include "trilogy-ruby.h"

#define CAST_STACK_SIZE 64

static ID id_BigDecimal, id_Integer, id_new, id_local, id_localtime, id_utc;

static const char *ruby_encoding_name_map[] = {
    [TRILOGY_ENCODING_ARMSCII8] = NULL,
    [TRILOGY_ENCODING_ASCII] = "US-ASCII",
    [TRILOGY_ENCODING_BIG5] = "Big5",
    [TRILOGY_ENCODING_BINARY] = "BINARY",
    [TRILOGY_ENCODING_CP1250] = "Windows-1250",
    [TRILOGY_ENCODING_CP1251] = "Windows-1251",
    [TRILOGY_ENCODING_CP1256] = "Windows-1256",
    [TRILOGY_ENCODING_CP1257] = "Windows-1257",
    [TRILOGY_ENCODING_CP850] = "CP850",
    [TRILOGY_ENCODING_CP852] = "CP852",
    [TRILOGY_ENCODING_CP866] = "IBM866",
    [TRILOGY_ENCODING_CP932] = "Windows-31J",
    [TRILOGY_ENCODING_DEC8] = NULL,
    [TRILOGY_ENCODING_EUCJPMS] = "eucJP-ms",
    [TRILOGY_ENCODING_EUCKR] = "EUC-KR",
    [TRILOGY_ENCODING_GB2312] = "GB2312",
    [TRILOGY_ENCODING_GBK] = "GBK",
    [TRILOGY_ENCODING_GEOSTD8] = NULL,
    [TRILOGY_ENCODING_GREEK] = "ISO-8859-7",
    [TRILOGY_ENCODING_HEBREW] = "ISO-8859-8",
    [TRILOGY_ENCODING_HP8] = NULL,
    [TRILOGY_ENCODING_KEYBCS2] = NULL,
    [TRILOGY_ENCODING_KOI8R] = "KOI8-R",
    [TRILOGY_ENCODING_KOI8U] = "KOI8-U",
    [TRILOGY_ENCODING_LATIN1] = "ISO-8859-1",
    [TRILOGY_ENCODING_LATIN2] = "ISO-8859-2",
    [TRILOGY_ENCODING_LATIN5] = "ISO-8859-9",
    [TRILOGY_ENCODING_LATIN7] = "ISO-8859-13",
    [TRILOGY_ENCODING_MACCE] = "macCentEuro",
    [TRILOGY_ENCODING_MACROMAN] = "macRoman",
    [TRILOGY_ENCODING_NONE] = NULL,
    [TRILOGY_ENCODING_SJIS] = "Shift_JIS",
    [TRILOGY_ENCODING_SWE7] = NULL,
    [TRILOGY_ENCODING_TIS620] = "TIS-620",
    [TRILOGY_ENCODING_UCS2] = "UTF-16BE",
    [TRILOGY_ENCODING_UJIS] = "eucJP-ms",
    [TRILOGY_ENCODING_UTF16] = "UTF-16BE",
    [TRILOGY_ENCODING_UTF32] = "UTF-32",
    [TRILOGY_ENCODING_UTF8] = "UTF-8",
    [TRILOGY_ENCODING_UTF8MB4] = "UTF-8",

    [TRILOGY_ENCODING_MAX] = NULL,
};

static int encoding_for_charset(TRILOGY_CHARSET_t charset)
{
    static int map[TRILOGY_CHARSET_MAX];

    if (map[charset]) {
        return map[charset];
    }

    const char *encoding_name = ruby_encoding_name_map[trilogy_encoding_from_charset(charset)];

    return map[charset] = (encoding_name ? rb_enc_find_index(encoding_name) : -1);
}

static void cstr_from_value(char *buf, const trilogy_value_t *value, const char *errmsg)
{

    if (value->data_len > CAST_STACK_SIZE - 1) {
        rb_raise(Trilogy_CastError, errmsg, (int)value->data_len, (char *)value->data);
    }

    memcpy(buf, value->data, value->data_len);
    buf[value->data_len] = 0;
}

static unsigned long long ull_from_buf(const char *digits, size_t len)
{
    if (!len)
        return 0;

    unsigned long long val = 0;

    while (len--) {
        unsigned digit = *digits++ - '0';
        val = val * 10 + digit;
    }

    return val;
}

static long long ll_from_buf(const char *digits, size_t len)
{
    if (!len)
        return 0;

    if (digits[0] == '-') {
        return -(long long)ull_from_buf(&digits[1], len - 1);
    } else {
        return (long long)ull_from_buf(digits, len);
    }
}

VALUE
rb_trilogy_cast_value(const trilogy_value_t *value, const struct column_info *column,
                      const struct rb_trilogy_cast_options *options)
{
    if (value->is_null) {
        return Qnil;
    }

    if (options->cast) {
        switch (column->type) {
        case TRILOGY_TYPE_BIT: {
            if (options->cast_booleans && column->len == 1) {
                return *(const char *)value->data == 1 ? Qtrue : Qfalse;
            }
            break;
        }
        case TRILOGY_TYPE_TINY: {
            if (options->cast_booleans && column->len == 1) {
                return *(const char *)value->data != '0' ? Qtrue : Qfalse;
            }
            /* fall through */
        }
        case TRILOGY_TYPE_SHORT:
        case TRILOGY_TYPE_LONG:
        case TRILOGY_TYPE_LONGLONG:
        case TRILOGY_TYPE_INT24:
        case TRILOGY_TYPE_YEAR: {
            if (column->flags & TRILOGY_COLUMN_FLAG_UNSIGNED) {
                unsigned long long num = ull_from_buf(value->data, value->data_len);
                return ULL2NUM(num);
            } else {
                long long num = ll_from_buf(value->data, value->data_len);
                return LL2NUM(num);
            }
        }
        case TRILOGY_TYPE_DECIMAL:
        case TRILOGY_TYPE_NEWDECIMAL: {
            // TODO - optimize so we don't have to allocate a ruby string for
            // decimal columns
            VALUE str = rb_str_new(value->data, value->data_len);
            if (column->decimals == 0 && !options->cast_decimals_to_bigdecimals) {
                return rb_funcall(rb_mKernel, id_Integer, 1, str);
            } else {
                return rb_funcall(rb_mKernel, id_BigDecimal, 1, str);
            }
        }
        case TRILOGY_TYPE_FLOAT:
        case TRILOGY_TYPE_DOUBLE: {
            char cstr[CAST_STACK_SIZE];
            cstr_from_value(cstr, value, "Invalid double value: %.*s");

            char *err;
            double dbl = strtod(cstr, &err);

            if (*err != 0) {
                rb_raise(Trilogy_CastError, "Invalid double value: %.*s", (int)value->data_len, (char *)value->data);
            }
            return rb_float_new(dbl);
        }
        case TRILOGY_TYPE_TIMESTAMP:
        case TRILOGY_TYPE_DATETIME: {
            int year, month, day, hour, min, sec;
            char msec_char[7] = {0};

            char cstr[CAST_STACK_SIZE];
            cstr_from_value(cstr, value, "Invalid date: %.*s");

            int tokens = sscanf(cstr, "%4u-%2u-%2u %2u:%2u:%2u.%6s", &year, &month, &day, &hour, &min, &sec, msec_char);

            // msec might not be present, so check for 6 tokens rather than 7
            if (tokens < 6) {
                return Qnil;
            }

            if (year == 0 && month == 0 && day == 0 && hour == 0 && min == 0 && sec == 0) {
                return Qnil;
            }

            if (month < 1 || day < 1) {
                rb_raise(Trilogy_CastError, "Invalid date: %.*s", (int)value->data_len, (char *)value->data);
            }

            // pad out msec_char with zeroes at the end as it could be at any
            // level of precision
            for (size_t i = strlen(msec_char); i < sizeof(msec_char) - 1; i++) {
                msec_char[i] = '0';
            }

            return rb_funcall(rb_cTime, options->database_local_time ? id_local : id_utc, 7, INT2NUM(year),
                              INT2NUM(month), INT2NUM(day), INT2NUM(hour), INT2NUM(min), INT2NUM(sec),
                              INT2NUM(atoi(msec_char)));
        }
        case TRILOGY_TYPE_DATE: {
            int year, month, day;

            char cstr[CAST_STACK_SIZE];
            cstr_from_value(cstr, value, "Invalid date: %.*s");

            int tokens = sscanf(cstr, "%4u-%2u-%2u", &year, &month, &day);
            VALUE Date = rb_const_get(rb_cObject, rb_intern("Date"));

            if (tokens < 3) {
                return Qnil;
            }

            if (year == 0 && month == 0 && day == 0) {
                return Qnil;
            }

            if (month < 1 || day < 1) {
                rb_raise(Trilogy_CastError, "Invalid date: %.*s", (int)value->data_len, (char *)value->data);
            }

            return rb_funcall(Date, id_new, 3, INT2NUM(year), INT2NUM(month), INT2NUM(day));
        }
        case TRILOGY_TYPE_TIME: {
            int hour, min, sec;
            char msec_char[7] = {0};

            char cstr[CAST_STACK_SIZE];
            cstr_from_value(cstr, value, "Invalid time: %.*s");

            int tokens = sscanf(cstr, "%2u:%2u:%2u.%6s", &hour, &min, &sec, msec_char);

            if (tokens < 3) {
                return Qnil;
            }

            // pad out msec_char with zeroes at the end as it could be at any
            // level of precision
            for (size_t i = strlen(msec_char); i < sizeof(msec_char) - 1; i++) {
                msec_char[i] = '0';
            }

            return rb_funcall(rb_cTime, options->database_local_time ? id_local : id_utc, 7, INT2NUM(2000), INT2NUM(1),
                              INT2NUM(1), INT2NUM(hour), INT2NUM(min), INT2NUM(sec), INT2NUM(atoi(msec_char)));
        }
        default:
            break;
        }
    }

    // for all other types, just return a string

    VALUE str = rb_str_new(value->data, value->data_len);

    int encoding_index = encoding_for_charset(column->charset);
    if (encoding_index != -1) {
        rb_enc_associate_index(str, encoding_index);
    }

    return str;
}

void rb_trilogy_cast_init(void)
{
    rb_require("bigdecimal");
    rb_require("date");

    id_BigDecimal = rb_intern("BigDecimal");
    id_Integer = rb_intern("Integer");
    id_new = rb_intern("new");
    id_local = rb_intern("local");
    id_localtime = rb_intern("localtime");
    id_utc = rb_intern("utc");
}
