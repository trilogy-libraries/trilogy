#ifndef TRILOGY_PLATFORM_H
#define TRILOGY_PLATFORM_H

/* Platform portability layer.
 *
 * Trilogy is written against POSIX sockets. On Windows the same API is provided
 * by Winsock 2, with a few differences that this header papers over so the
 * rest of the library can stay platform agnostic:
 *
 *   - socket headers live in <winsock2.h>/<ws2tcpip.h>/<afunix.h>
 *   - MSVC has no ssize_t
 *   - sockets are SOCKET handles rather than ints. Like OpenSSL's SSL_set_fd,
 *     Trilogy keeps passing them around as `int`; Windows guarantees socket
 *     handle values fit in 32 bits, so the conversion is lossless.
 */

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include <basetsd.h>

/* <winsock2.h> pulls in <windows.h> and with it <wincrypt.h>, whose macros
 * collide with OpenSSL type names. OpenSSL undefines them itself, but only
 * if its headers are included after <windows.h>; do it here so include
 * order does not matter. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE

#if defined(_MSC_VER) && !defined(_SSIZE_T_DEFINED)
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif

#else /* POSIX */

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#endif

#endif
