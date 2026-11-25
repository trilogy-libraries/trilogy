#include "trilogy/platform.h"

#ifdef _WIN32
#include <limits.h>
#if defined(__has_include)
#if __has_include(<afunix.h>)
#include <afunix.h>
#define TRILOGY_HAVE_AFUNIX_H
#endif
#endif
#ifndef TRILOGY_HAVE_AFUNIX_H
// Older SDKs lack <afunix.h>; AF_UNIX itself is supported since Windows 10 1803.
#define UNIX_PATH_MAX 108
struct sockaddr_un {
    ADDRESS_FAMILY sun_family;
    char sun_path[UNIX_PATH_MAX];
};
#endif
#ifndef PF_UNIX
#define PF_UNIX AF_UNIX
#endif
#else
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/un.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "trilogy/allocator.h"
#include "trilogy/error.h"
#include "trilogy/socket.h"

/* System call shims.
 *
 * Every function below behaves like its POSIX namesake: it returns -1 on
 * failure with the reason in `errno`. On Windows the Winsock error is
 * translated into the equivalent errno value, because Trilogy's contract is
 * that callers inspect `errno` after a TRILOGY_SYSERR.
 */
#ifdef _WIN32

#define TRILOGY_SOCKET(fd) ((SOCKET)(fd))

static int trilogy_wsa_to_errno(int err)
{
    switch (err) {
    case 0:
        return 0;
    case WSAEINTR:
        return EINTR;
    case WSAEWOULDBLOCK:
        return EAGAIN;
    case WSAEINPROGRESS:
    case WSAEALREADY:
        return EINPROGRESS;
    case WSAEBADF:
    case WSAENOTSOCK:
        return EBADF;
    case WSAEACCES:
        return EACCES;
    case WSAEFAULT:
        return EFAULT;
    case WSAEINVAL:
        return EINVAL;
    case WSAEMFILE:
        return EMFILE;
    case WSAEMSGSIZE:
        return EMSGSIZE;
    case WSAEAFNOSUPPORT:
        return EAFNOSUPPORT;
    case WSAEADDRINUSE:
        return EADDRINUSE;
    case WSAEADDRNOTAVAIL:
        return EADDRNOTAVAIL;
    case WSAENETDOWN:
        return ENETDOWN;
    case WSAENETUNREACH:
        return ENETUNREACH;
    case WSAENETRESET:
        return ENETRESET;
    case WSAECONNABORTED:
        return ECONNABORTED;
    case WSAECONNRESET:
        return ECONNRESET;
    case WSAENOBUFS:
        return ENOBUFS;
    case WSAEISCONN:
        return EISCONN;
    case WSAENOTCONN:
        return ENOTCONN;
    case WSAESHUTDOWN:
        return EPIPE;
    case WSAETIMEDOUT:
        return ETIMEDOUT;
    case WSAECONNREFUSED:
        return ECONNREFUSED;
    case WSAEHOSTUNREACH:
        return EHOSTUNREACH;
    default:
        return EIO;
    }
}

// Copy the last Winsock error into errno and return it.
static int sys_sock_errno(void)
{
    errno = trilogy_wsa_to_errno(WSAGetLastError());
    return errno;
}

static int sys_socket(int domain, int type, int protocol)
{
    SOCKET s = socket(domain, type, protocol);
    if (s == INVALID_SOCKET) {
        sys_sock_errno();
        return -1;
    }
    return (int)s;
}

static int sys_close(int fd)
{
    if (closesocket(TRILOGY_SOCKET(fd)) == SOCKET_ERROR) {
        sys_sock_errno();
        return -1;
    }
    return 0;
}

static int clamp_len(size_t len) { return len > INT_MAX ? INT_MAX : (int)len; }

static ssize_t sys_recv(int fd, void *buf, size_t len, int flags)
{
    int n = recv(TRILOGY_SOCKET(fd), (char *)buf, clamp_len(len), flags);
    if (n == SOCKET_ERROR) {
        // After shutdown(SHUT_RD) POSIX reports end-of-file; Winsock reports
        // WSAESHUTDOWN. Normalise to end-of-file.
        if (WSAGetLastError() == WSAESHUTDOWN) {
            return 0;
        }
        sys_sock_errno();
        return -1;
    }
    return n;
}

static ssize_t sys_read(int fd, void *buf, size_t len) { return sys_recv(fd, buf, len, 0); }

static ssize_t sys_write(int fd, const void *buf, size_t len)
{
    int n = send(TRILOGY_SOCKET(fd), (const char *)buf, clamp_len(len), 0);
    if (n == SOCKET_ERROR) {
        // Writing to a connection the peer has torn down fails with EPIPE on
        // POSIX but with a reset/abort on Windows; report it the POSIX way so
        // callers get TRILOGY_CLOSED_CONNECTION on both.
        int err = WSAGetLastError();
        if (err == WSAECONNRESET || err == WSAECONNABORTED) {
            errno = EPIPE;
        } else {
            sys_sock_errno();
        }
        return -1;
    }
    return n;
}

static int sys_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    if (setsockopt(TRILOGY_SOCKET(fd), level, name, (const char *)val, len) == SOCKET_ERROR) {
        sys_sock_errno();
        return -1;
    }
    return 0;
}

static int sys_set_nonblocking(int fd)
{
    u_long mode = 1;
    if (ioctlsocket(TRILOGY_SOCKET(fd), (long)FIONBIO, &mode) == SOCKET_ERROR) {
        sys_sock_errno();
        return -1;
    }
    return 0;
}

// select() rather than WSAPoll(): WSAPoll fails to report a refused
// non-blocking connect on many Windows versions, while select() reports it
// through the exception set. With one socket, FD_SETSIZE is not a concern.
static int sys_wait(int fd, trilogy_wait_t wait)
{
    fd_set rfds, wfds, efds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    switch (wait) {
    case TRILOGY_WAIT_HANDSHAKE:
    case TRILOGY_WAIT_READ:
        FD_SET(TRILOGY_SOCKET(fd), &rfds);
        break;
    case TRILOGY_WAIT_CONNECT:
        FD_SET(TRILOGY_SOCKET(fd), &wfds);
        FD_SET(TRILOGY_SOCKET(fd), &efds);
        break;
    case TRILOGY_WAIT_WRITE:
        FD_SET(TRILOGY_SOCKET(fd), &wfds);
        break;
    default:
        return TRILOGY_ERR;
    }

    while (1) {
        if (select(0, &rfds, &wfds, &efds, NULL) == SOCKET_ERROR) {
            if (sys_sock_errno() == EINTR) {
                continue;
            }
            return TRILOGY_SYSERR;
        }
        return TRILOGY_OK;
    }
}

#else /* POSIX */

#define TRILOGY_SOCKET(fd) (fd)

static int sys_sock_errno(void) { return errno; }

static int sys_socket(int domain, int type, int protocol) { return socket(domain, type, protocol); }

static int sys_close(int fd) { return close(fd); }

static ssize_t sys_recv(int fd, void *buf, size_t len, int flags) { return recv(fd, buf, len, flags); }

static ssize_t sys_read(int fd, void *buf, size_t len) { return read(fd, buf, len); }

static ssize_t sys_write(int fd, const void *buf, size_t len) { return write(fd, buf, len); }

static int sys_setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
    return setsockopt(fd, level, name, val, len);
}

static int sys_set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    return 0;
}

static int sys_wait(int fd, trilogy_wait_t wait)
{
    struct pollfd pfd = {.fd = fd};

    switch (wait) {
    case TRILOGY_WAIT_HANDSHAKE:
    case TRILOGY_WAIT_READ:
        pfd.events = POLLIN;
        break;
    case TRILOGY_WAIT_CONNECT:
    case TRILOGY_WAIT_WRITE:
        pfd.events = POLLOUT;
        break;
    default:
        return TRILOGY_ERR;
    }

    while (1) {
        int rc = poll(&pfd, 1, -1);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return TRILOGY_SYSERR;
        }

        return TRILOGY_OK;
    }
}

#endif

#if OPENSSL_VERSION_NUMBER < 0x1000200fL
#include "trilogy/vendor/openssl_hostname_validation.h"
#endif

struct trilogy_sock {
    trilogy_sock_t base;
    struct addrinfo *addr;
    SSL *ssl;
    int fd;
    bool freeaddrinfo;
#ifdef _WIN32
    bool wsa_started;
#endif
};

void trilogy_sock_set_fd(trilogy_sock_t *_sock, int fd)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    sock->fd = fd;
}

static int _cb_raw_fd(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    return sock->fd;
}

static int _cb_wait(trilogy_sock_t *_sock, trilogy_wait_t wait) { return sys_wait(trilogy_sock_fd(_sock), wait); }

static ssize_t _cb_raw_read(trilogy_sock_t *_sock, void *buf, size_t nread)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    ssize_t data_read = sys_read(sock->fd, buf, nread);
    if (data_read < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            return (ssize_t)TRILOGY_AGAIN;
        } else {
            return (ssize_t)TRILOGY_SYSERR;
        }
    }
    return data_read;
}

static ssize_t _cb_raw_write(trilogy_sock_t *_sock, const void *buf, size_t nwrite)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    ssize_t data_written = sys_write(sock->fd, buf, nwrite);
    if (data_written < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            return (ssize_t)TRILOGY_AGAIN;
        }

        if (errno == EPIPE) {
            return (ssize_t)TRILOGY_CLOSED_CONNECTION;
        }

        return (ssize_t)TRILOGY_SYSERR;
    }
    return data_written;
}

static int _cb_raw_close(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    int rc = 0;
    if (sock->fd != -1) {
        rc = sys_close(sock->fd);
    }

    if (sock->addr) {
        if (sock->freeaddrinfo) {
            freeaddrinfo(sock->addr);
        } else {
            /* We created these with xcalloc so must free them instead of calling freeaddrinfo */
            xfree(sock->addr->ai_addr);
            xfree(sock->addr);
        }
    }

    xfree(sock->base.opts.hostname);
    xfree(sock->base.opts.path);
    xfree(sock->base.opts.database);
    xfree(sock->base.opts.username);
    xfree(sock->base.opts.password);
    xfree(sock->base.opts.ssl_ca);
    xfree(sock->base.opts.ssl_capath);
    xfree(sock->base.opts.ssl_cert);
    xfree(sock->base.opts.ssl_cipher);
    xfree(sock->base.opts.ssl_crl);
    xfree(sock->base.opts.ssl_crlpath);
    xfree(sock->base.opts.ssl_key);
    xfree(sock->base.opts.tls_ciphersuites);

#ifdef _WIN32
    if (sock->wsa_started) {
        WSACleanup();
    }
#endif

    xfree(sock);
    return rc;
}

static int _cb_shutdown_connect(trilogy_sock_t *_sock) {
    (void)_sock;
    return TRILOGY_CLOSED_CONNECTION;
}
static ssize_t _cb_shutdown_write(trilogy_sock_t *_sock, const void *buf, size_t nwrite) {
    (void)_sock;
    (void)buf;
    (void)nwrite;
    return TRILOGY_CLOSED_CONNECTION;
}
static ssize_t _cb_shutdown_read(trilogy_sock_t *_sock, void *buf, size_t nread) {
    (void)_sock;
    (void)buf;
    (void)nread;
    return TRILOGY_CLOSED_CONNECTION;
}
static int _cb_shutdown_wait(trilogy_sock_t *_sock, trilogy_wait_t wait) {
    (void)_sock;
    (void)wait;
    return TRILOGY_OK;
}
static int _cb_shutdown_shutdown(trilogy_sock_t *_sock) {
    (void)_sock;
    return TRILOGY_OK;
}

// Shutdown will close the underlying socket fd and replace all I/O operations with stubs which perform no action.
static int _cb_raw_shutdown(trilogy_sock_t *_sock) {
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    // Replace all operations with stubs which return immediately
    sock->base.connect_cb = _cb_shutdown_connect;
    sock->base.read_cb = _cb_shutdown_read;
    sock->base.write_cb = _cb_shutdown_write;
    sock->base.wait_cb = _cb_shutdown_wait;
    sock->base.shutdown_cb = _cb_shutdown_shutdown;

    // These "raw" callbacks won't attempt further operations on the socket and work correctly with fd set to -1
    sock->base.close_cb = _cb_raw_close;
    sock->base.fd_cb = _cb_raw_fd;

    if (sock->fd != -1)
        sys_close(sock->fd);
    sock->fd = -1;

    return TRILOGY_OK;
}

static int set_nonblocking_fd(int sock)
{
    if (sys_set_nonblocking(sock) < 0) {
        return TRILOGY_SYSERR;
    }

    return TRILOGY_OK;
}

static int raw_connect_internal(struct trilogy_sock *sock, const struct addrinfo *ai)
{
    int sockerr;
    socklen_t sockerr_len = sizeof(sockerr);
    int rc = TRILOGY_SYSERR;

    sock->fd = sys_socket(ai->ai_family, SOCK_STREAM, ai->ai_protocol);
    if (sock->fd < 0) {
        return TRILOGY_SYSERR;
    }

#ifdef TCP_NODELAY
    if (sock->addr->ai_family != PF_UNIX) {
        int flags = 1;
        if (sys_setsockopt(sock->fd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags)) < 0) {
            goto fail;
        }
    }
#endif
    if (sock->base.opts.keepalive_enabled) {
        int flags = 1;
        if (sys_setsockopt(sock->fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags)) < 0) {
            goto fail;
        }
#ifdef TCP_KEEPIDLE
        if (sock->base.opts.keepalive_idle > 0) {
            flags = sock->base.opts.keepalive_idle;
            if (sys_setsockopt(sock->fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&flags, sizeof(flags)) < 0) {
                goto fail;
            }
        }
#endif
#ifdef TCP_KEEPINTVL
        if (sock->base.opts.keepalive_interval > 0) {
            flags = sock->base.opts.keepalive_interval;
            if (sys_setsockopt(sock->fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&flags, sizeof(flags)) < 0) {
                goto fail;
            }
        }
#endif
#ifdef TCP_KEEPCNT
        if (sock->base.opts.keepalive_count > 0) {
            flags = sock->base.opts.keepalive_count;
            if (sys_setsockopt(sock->fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&flags, sizeof(flags)) < 0) {
                goto fail;
            }
        }
#endif
    }

    if (set_nonblocking_fd(sock->fd) < 0) {
        goto fail;
    }

    if (connect(TRILOGY_SOCKET(sock->fd), ai->ai_addr, (socklen_t)ai->ai_addrlen) < 0) {
        int err = sys_sock_errno();
        if (err != EINPROGRESS && err != EAGAIN) {
            goto fail;
        }
    }

    if ((rc = trilogy_sock_wait((trilogy_sock_t *)sock, TRILOGY_WAIT_CONNECT)) < 0) {
        goto failrc;
    }

    if (getsockopt(TRILOGY_SOCKET(sock->fd), SOL_SOCKET, SO_ERROR, (void *)&sockerr, &sockerr_len) < 0) {
        sys_sock_errno();
        goto fail;
    }

    if (sockerr != 0) {
        // the socket failed to connect; since `getsockopt` doesn't set `errno`
        // to a meaningful value, we must set it manually because clients always
        // expect to find the error code there
#ifdef _WIN32
        errno = trilogy_wsa_to_errno(sockerr);
#else
        errno = sockerr;
#endif
        goto fail;
    }

    return TRILOGY_OK;

fail:
    rc = TRILOGY_SYSERR;
failrc:
    sys_close(sock->fd);
    sock->fd = -1;
    return rc;
}

static int _cb_raw_connect(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    const struct addrinfo *ai = sock->addr;

    for (; ai; ai = ai->ai_next) {
        int rc = raw_connect_internal(sock, ai);
        if (rc == TRILOGY_OK)
            return TRILOGY_OK;
        else if (!ai->ai_next)
            return rc;
    }

    return TRILOGY_ERR;
}

static char *strdupnullok(const char *str)
{
    if (str == NULL) {
        return NULL;
    }
    return xstrdup(str);
}

trilogy_sock_t *trilogy_sock_new(const trilogy_sockopt_t *opts)
{
    struct trilogy_sock *sock = xmalloc(sizeof(struct trilogy_sock));

    sock->base.connect_cb = _cb_raw_connect;
    sock->base.read_cb = _cb_raw_read;
    sock->base.write_cb = _cb_raw_write;
    sock->base.wait_cb = _cb_wait;
    sock->base.shutdown_cb = _cb_raw_shutdown;
    sock->base.close_cb = _cb_raw_close;
    sock->base.fd_cb = _cb_raw_fd;
    sock->base.opts = *opts;

    sock->base.opts.hostname = strdupnullok(opts->hostname);
    sock->base.opts.path = strdupnullok(opts->path);
    sock->base.opts.database = strdupnullok(opts->database);
    sock->base.opts.username = strdupnullok(opts->username);

    if (sock->base.opts.password) {
        sock->base.opts.password = xmalloc(opts->password_len);
        memcpy(sock->base.opts.password, opts->password, opts->password_len);
    }

    sock->base.opts.ssl_ca = strdupnullok(opts->ssl_ca);
    sock->base.opts.ssl_capath = strdupnullok(opts->ssl_capath);
    sock->base.opts.ssl_cert = strdupnullok(opts->ssl_cert);
    sock->base.opts.ssl_cipher = strdupnullok(opts->ssl_cipher);
    sock->base.opts.ssl_crl = strdupnullok(opts->ssl_crl);
    sock->base.opts.ssl_crlpath = strdupnullok(opts->ssl_crlpath);
    sock->base.opts.ssl_key = strdupnullok(opts->ssl_key);
    sock->base.opts.tls_ciphersuites = strdupnullok(opts->tls_ciphersuites);

    sock->fd = -1;
    sock->addr = NULL;
    sock->ssl = NULL;

#ifdef _WIN32
    // Winsock must be initialised before any socket or resolver call. It is
    // reference counted, so every socket takes a reference and releases it in
    // _cb_raw_close. If this fails, later calls fail with a system error.
    WSADATA wsa_data;
    sock->wsa_started = WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
#endif

    return (trilogy_sock_t *)sock;
}

int trilogy_sock_resolve(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    if (sock->base.opts.hostname != NULL) {
        struct addrinfo hint = {.ai_family = PF_UNSPEC, .ai_socktype = SOCK_STREAM};

        char port[6];
        snprintf(port, sizeof(port), "%hu", sock->base.opts.port);

        sock->freeaddrinfo = true;
        if (getaddrinfo(sock->base.opts.hostname, port, &hint, &sock->addr) != 0) {
            return TRILOGY_DNS_ERR;
        }
    } else if (sock->base.opts.path != NULL) {
        struct sockaddr_un *sa;

        if (strlen(sock->base.opts.path) + 1 > sizeof(sa->sun_path)) {
            goto fail;
        }

        sa = xcalloc(1, sizeof(struct sockaddr_un));
        sa->sun_family = AF_UNIX;
        strcpy(sa->sun_path, sock->base.opts.path);

        sock->addr = xcalloc(1, sizeof(struct addrinfo));
        sock->addr->ai_family = PF_UNIX;
        sock->addr->ai_socktype = SOCK_STREAM;
        sock->addr->ai_addr = (struct sockaddr *)sa;
        sock->addr->ai_addrlen = sizeof(struct sockaddr_un);
        sock->freeaddrinfo = false;
    } else {
        goto fail;
    }

    return TRILOGY_OK;

fail:
    _cb_raw_close(_sock);
    return TRILOGY_ERR;
}

static ssize_t ssl_io_return(struct trilogy_sock *sock, ssize_t ret)
{
    if (ret <= 0) {
        int rc = SSL_get_error(sock->ssl, (int)ret);
        if (rc == SSL_ERROR_WANT_WRITE || rc == SSL_ERROR_WANT_READ) {
            return (ssize_t)TRILOGY_AGAIN;
        } else if (rc == SSL_ERROR_ZERO_RETURN) {
            // Server has closed the connection for writing by sending the close_notify alert
            return (ssize_t)TRILOGY_CLOSED_CONNECTION;
        } else if (rc == SSL_ERROR_SYSCALL && !ERR_peek_error()) {
#ifdef _WIN32
            // OpenSSL's socket BIO reports failures through WSAGetLastError.
            if (WSAGetLastError() != 0) {
                sys_sock_errno();
                return (ssize_t)TRILOGY_SYSERR;
            }
            return (ssize_t)TRILOGY_CLOSED_CONNECTION;
#else
            if (errno == 0) {
                // On OpenSSL <= 1.1.1, SSL_ERROR_SYSCALL with an errno value
                // of 0 indicates unexpected EOF from the peer.
                return (ssize_t)TRILOGY_CLOSED_CONNECTION;
            } else {
                return (ssize_t)TRILOGY_SYSERR;
            }
#endif
        }
        return (ssize_t)TRILOGY_OPENSSL_ERR;
    }
    return ret;
}

static ssize_t _cb_ssl_read(trilogy_sock_t *_sock, void *buf, size_t nread)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    // This shouldn't be necessary, but protects against other libraries in the same process incorrectly leaving errors
    // in the queue.
    ERR_clear_error();

#ifdef _WIN32
    WSASetLastError(0);
#endif
    ssize_t data_read = (ssize_t)SSL_read(sock->ssl, buf, (int)nread);
    return ssl_io_return(sock, data_read);
}

static ssize_t _cb_ssl_write(trilogy_sock_t *_sock, const void *buf, size_t nwrite)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    // This shouldn't be necessary, but protects against other libraries in the same process incorrectly leaving errors
    // in the queue.
    ERR_clear_error();

#ifdef _WIN32
    WSASetLastError(0);
#endif
    ssize_t data_written = (ssize_t)SSL_write(sock->ssl, buf, (int)nwrite);
    return ssl_io_return(sock, data_written);
}

static int _cb_ssl_shutdown(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    // If we have an SSL socket, it's invalid here and
    // we need to close it. The OpenSSL explicitly states
    // not to call SSL_shutdown on a broken SSL socket.
    SSL_free(sock->ssl);
    sock->ssl = NULL;

    // This will rewrite the handlers
    return _cb_raw_shutdown(_sock);
}

static int _cb_ssl_close(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    if (sock->ssl != NULL) {
        if (SSL_in_init(sock->ssl) == 0) {
            (void)SSL_shutdown(sock->ssl);
            // SSL_shutdown might return WANT_WRITE or WANT_READ. Ideally we would retry but we don't want to block.
            // It may also push an error onto the OpenSSL error queue, so clear that.
            ERR_clear_error();
        }
        SSL_free(sock->ssl);
        sock->ssl = NULL;
    }
    return _cb_raw_close(_sock);
}

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL

static int trilogy_tls_version_map[] = {0, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION
#ifdef TLS1_3_VERSION
                                        ,
                                        TLS1_3_VERSION
#else
                                        ,
                                        0
#endif
};

long trilogy_set_min_proto_version(SSL_CTX *ctx, trilogy_tls_version_t version)
{
    int ssl_ver = trilogy_tls_version_map[version];
    if (ssl_ver == 0) {
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_UNSUPPORTED_PROTOCOL, NULL, 0);
        return 0;
    }
    return SSL_CTX_set_min_proto_version(ctx, ssl_ver);
}

long trilogy_set_max_proto_version(SSL_CTX *ctx, trilogy_tls_version_t version)
{
    int ssl_ver = trilogy_tls_version_map[version];
    if (ssl_ver == 0) {
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_UNSUPPORTED_PROTOCOL, NULL, 0);
        return 0;
    }
    return SSL_CTX_set_max_proto_version(ctx, ssl_ver);
}
#else

int trilogy_set_min_proto_version(SSL_CTX *ctx, trilogy_tls_version_t version)
{
    long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    switch (version) {
    case TRILOGY_TLS_VERSION_13:
        opts |= SSL_OP_NO_TLSv1_2;
    case TRILOGY_TLS_VERSION_12:
        opts |= SSL_OP_NO_TLSv1_1;
    case TRILOGY_TLS_VERSION_11:
        opts |= SSL_OP_NO_TLSv1;
    default:
        break;
    }
    // No need to handle 1.3 here since OpenSSL < 1.1.0 doesn't support that
    // anyway
    SSL_CTX_set_options(ctx, opts);
    return 1;
}

int trilogy_set_max_proto_version(SSL_CTX *ctx, trilogy_tls_version_t version)
{
    long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    switch (version) {
    case TRILOGY_TLS_VERSION_10:
        opts |= SSL_OP_NO_TLSv1_1;
    case TRILOGY_TLS_VERSION_11:
        opts |= SSL_OP_NO_TLSv1_2;
    default:
        break;
    }
    SSL_CTX_set_options(ctx, opts);
    return 1;
}
#endif

static SSL_CTX *trilogy_ssl_ctx(const trilogy_sockopt_t *opts)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());

    // Now handle all the custom options that we're given.
    if (opts->tls_min_version != TRILOGY_TLS_VERSION_UNDEF) {
        if (!trilogy_set_min_proto_version(ssl_ctx, opts->tls_min_version)) {
            goto fail;
        }
    } else {
        if (!trilogy_set_min_proto_version(ssl_ctx, TRILOGY_TLS_VERSION_12)) {
            goto fail;
        }
    }

    if (opts->tls_max_version != TRILOGY_TLS_VERSION_UNDEF) {
        if (!trilogy_set_max_proto_version(ssl_ctx, opts->tls_max_version)) {
            goto fail;
        }
    }

    if (opts->ssl_cipher) {
        if (!SSL_CTX_set_cipher_list(ssl_ctx, opts->ssl_cipher)) {
            goto fail;
        }
    } else {
        // Use a secure cipher list, based on TLS 1.2 and with authenticated
        // encryption.
        if (!SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                                              "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                                              "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")) {
            goto fail;
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
    if (opts->tls_ciphersuites) {
        if (!SSL_CTX_set_ciphersuites(ssl_ctx, opts->tls_ciphersuites)) {
            goto fail;
        }
    }
#endif

    switch (opts->ssl_mode) {
    case TRILOGY_SSL_DISABLED:
        break;
    case TRILOGY_SSL_VERIFY_IDENTITY:
    case TRILOGY_SSL_VERIFY_CA:
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        break;
    case TRILOGY_SSL_REQUIRED_NOVERIFY:
    case TRILOGY_SSL_PREFERRED_NOVERIFY:
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        break;
    }

    if (opts->ssl_ca || opts->ssl_capath) {
        if (!SSL_CTX_load_verify_locations(ssl_ctx, opts->ssl_ca, opts->ssl_capath)) {
            goto fail;
        }
    } else {
        // Use the default systems paths to verify the certificate
        if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
            goto fail;
        }
    }

    if (opts->ssl_cert || opts->ssl_key) {
        if (opts->ssl_key) {
            if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, opts->ssl_key, SSL_FILETYPE_PEM)) {
                goto fail;
            }
        }
        if (opts->ssl_cert) {
            if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, opts->ssl_cert)) {
                goto fail;
            }
        }

        if (!SSL_CTX_check_private_key(ssl_ctx)) {
            goto fail;
        }
    }

    if (opts->ssl_crl || opts->ssl_crlpath) {
        X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);

        if (!X509_STORE_load_locations(store, opts->ssl_crl, opts->ssl_crlpath)) {
            goto fail;
        }

        if (!X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) {
            goto fail;
        }
    }
    return ssl_ctx;

fail:
    SSL_CTX_free(ssl_ctx);
    return NULL;
}

int trilogy_sock_upgrade_ssl(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;

    // This shouldn't be necessary, but protects against other libraries in the same process incorrectly leaving errors
    // in the queue.
    ERR_clear_error();

    SSL_CTX *ctx = trilogy_ssl_ctx(&sock->base.opts);

    if (!ctx) {
        return TRILOGY_OPENSSL_ERR;
    }

    sock->ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);

    if (sock->base.opts.ssl_mode == TRILOGY_SSL_VERIFY_IDENTITY && sock->base.opts.hostname == NULL) {
        // If hostname validation is requested and no hostname provided, treat it as an error.
#ifdef SSL_F_TLS_PROCESS_SERVER_CERTIFICATE
        ERR_put_error(ERR_LIB_SSL, SSL_F_TLS_PROCESS_SERVER_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED, NULL, 0);
#else
        ERR_put_error(ERR_LIB_SSL, SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED, NULL, 0);
#endif
        goto fail;
    }

    // Set the SNI hostname for the connection
    if (sock->base.opts.hostname != NULL) {
        if (!SSL_set_tlsext_host_name(sock->ssl, sock->base.opts.hostname)) {
            goto fail;
        }
    }

    // Newer API available since 1.0.2, so we don't have to do manual work.
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
    if (sock->base.opts.ssl_mode == TRILOGY_SSL_VERIFY_IDENTITY) {
        X509_VERIFY_PARAM *param = SSL_get0_param(sock->ssl);
        const char *hostname = sock->base.opts.hostname;
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (!X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname))) {
            goto fail;
        }
    }
#endif

    if (!SSL_set_fd(sock->ssl, sock->fd))
        goto fail;

    for (;;) {
        // This shouldn't be necessary, but protects against other libraries in the same process incorrectly leaving errors
        // in the queue.
        ERR_clear_error();

        int ret = SSL_connect(sock->ssl);
        if (ret == 1) {
#if OPENSSL_VERSION_NUMBER < 0x1000200fL
            if (sock->base.opts.ssl_mode == TRILOGY_SSL_VERIFY_IDENTITY) {
                if (validate_hostname(sock->base.opts.hostname, SSL_get_peer_certificate(sock->ssl)) != MatchFound) {
                    // Fake the error message to be the same as it would be on 1.0.2 and newer.
                    ERR_put_error(ERR_LIB_SSL, SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED, NULL,
                                  0);
                    goto fail;
                }
            }
#endif
            break;
        }

        switch (SSL_get_error(sock->ssl, ret)) {
        case SSL_ERROR_WANT_READ:
            if (trilogy_sock_wait_read(_sock) < 0)
                goto fail;
            break;

        case SSL_ERROR_WANT_WRITE:
            if (trilogy_sock_wait_write(_sock) < 0)
                goto fail;
            break;

        default:
            goto fail;
        }
    }

    sock->base.read_cb = _cb_ssl_read;
    sock->base.write_cb = _cb_ssl_write;
    sock->base.shutdown_cb = _cb_ssl_shutdown;
    sock->base.close_cb = _cb_ssl_close;
    return TRILOGY_OK;

fail:
    SSL_free(sock->ssl);
    sock->ssl = NULL;
    return TRILOGY_OPENSSL_ERR;
}

int trilogy_sock_check(trilogy_sock_t *_sock)
{
    struct trilogy_sock *sock = (struct trilogy_sock *)_sock;
    char buf[1];
    while (1) {
        ssize_t data_read = sys_recv(sock->fd, buf, 1, MSG_PEEK);
        if (data_read > 0) {
            return TRILOGY_OK;
        }
        if (data_read == 0) {
            return TRILOGY_CLOSED_CONNECTION;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return TRILOGY_OK;
        }
        return TRILOGY_SYSERR;
    }
}
