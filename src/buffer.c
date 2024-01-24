#include <stdint.h>
#include <stdlib.h>

#include "trilogy/buffer.h"
#include "trilogy/error.h"

int trilogy_buffer_init(trilogy_buffer_t *buffer, size_t initial_capacity)
{
    buffer->len = 0;
    buffer->cap = initial_capacity;
    buffer->buff = malloc(initial_capacity);

    if (buffer->buff == NULL) {
        return TRILOGY_SYSERR;
    }

    return TRILOGY_OK;
}

#define EXPAND_MULTIPLIER 2

int trilogy_buffer_expand(trilogy_buffer_t *buffer, size_t needed)
{
    // expand buffer if necessary
    if (buffer->len + needed > buffer->cap) {
        size_t new_cap = buffer->cap;

        while (buffer->len + needed > new_cap) {
            // would this next step cause an overflow?
            if (new_cap > SIZE_MAX / EXPAND_MULTIPLIER)
                return TRILOGY_TYPE_OVERFLOW;

            new_cap *= EXPAND_MULTIPLIER;
        }

        uint8_t *new_buff = realloc(buffer->buff, new_cap);
        if (new_buff == NULL)
            return TRILOGY_SYSERR;

        buffer->buff = new_buff;
        buffer->cap = new_cap;
    }

    return TRILOGY_OK;
}

int trilogy_buffer_putc(trilogy_buffer_t *buffer, uint8_t c)
{
    int rc = trilogy_buffer_expand(buffer, 1);

    if (rc) {
        return rc;
    }

    buffer->buff[buffer->len++] = c;

    return TRILOGY_OK;
}

void trilogy_buffer_free(trilogy_buffer_t *buffer)
{
    free(buffer->buff);
    buffer->buff = NULL;
    buffer->len = buffer->cap = 0;
}
