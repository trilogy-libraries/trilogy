#ifndef TRILOGY_XALLOCATOR_H
#define TRILOGY_XALLOCATOR_H

#ifdef _WIN32

/* On Windows <ruby.h> redefines recv, send, select, FD_SET and friends as
 * wrappers that take C runtime file descriptors. The Trilogy library works on
 * Winsock SOCKETs directly, so it must not see those macros: declare Ruby's
 * allocator by hand rather than including <ruby.h>. Sources that have already
 * included <ruby.h> get the allocator from there. */
#ifndef xmalloc
#include <stddef.h>

void *ruby_xmalloc(size_t size);
void *ruby_xcalloc(size_t nelems, size_t elemsiz);
void *ruby_xrealloc(void *ptr, size_t newsiz);
void ruby_xfree(void *ptr);

#define xmalloc ruby_xmalloc
#define xcalloc ruby_xcalloc
#define xrealloc ruby_xrealloc
#define xfree ruby_xfree
#endif

#else

#include <ruby.h>

#endif

#endif
