# Trilogy

Trilogy is a client library for MySQL-compatible database servers, designed for performance, flexibility, and ease of embedding.

It's currently in production use on github.com.

## Features

* Supports the most frequently used parts of the text protocol
    * Handshake
    * Password authentication
    * Query, ping, and quit commands

* Support prepared statements (binary protocol)

* Low-level protocol API completely decoupled from IO

* Non-blocking client API wrapping the protocol API

* Blocking client API wrapping the non-blocking API

* No dependencies outside of POSIX (or Winsock on Windows), the C standard library & OpenSSL

* Minimal dynamic allocation

* MIT licensed

## Limitations

* Only supports the parts of the text protocol that are in common use.

* No support for `LOAD DATA INFILE` on local files

* `trilogy_escape` assumes an ASCII-compatible connection encoding

## Building

`make` - that's it. This will build a static `libtrilogy.a`

Trilogy should build out of the box on most UNIX systems which have OpenSSL installed.

### Windows

Trilogy supports Windows 10 and later (Unix domain sockets need Windows 10 version 1803 or later). OpenSSL is required on Windows too.

With [MSYS2](https://www.msys2.org/) (MinGW-w64), install `make`, `mingw-w64-ucrt-x86_64-gcc` and `mingw-w64-ucrt-x86_64-openssl`, then run `make` from a UCRT64 shell. Link programs that use Trilogy against `-lssl -lcrypto -lws2_32 -lcrypt32`.

With Visual Studio, use the CMake build:

```
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL"
cmake --build build --config Release
```

The CMake target `trilogy` links Winsock (`ws2_32`) for you. Pass `-DTRILOGY_BUILD_TESTS=ON` to build the test suite as well.

Notes for Windows:

* Socket handles are passed through the API as `int` (for example `trilogy_sock_fd` and `trilogy_connect_set_fd`), as OpenSSL's `SSL_set_fd` does. Cast them to `SOCKET` before calling Winsock functions.
* After `TRILOGY_SYSERR`, `errno` holds the POSIX equivalent of the Winsock error (`ECONNREFUSED`, `ETIMEDOUT` and so on), so the same error handling works on every platform.
* OpenSSL has no system certificate store on Windows, so set `ssl_ca` when verifying server certificates.
* The Ruby binding in `contrib/ruby` builds with [RubyInstaller](https://rubyinstaller.org/) and its MSYS2 toolchain; see its README.

## API Documentation

Documentation for Trilogy's various APIs can be found in these header files:

* `blocking.h`

    The blocking client API. These are simply a set of convenient wrapper functions around the non-blocking client API in `client.h`

* `client.h`

    The non-blocking client API. Every command is split into a `_send` and `_recv` function allowing callers to wait for IO readiness externally to Trilogy

* `builder.h`

    MySQL-compatible packet builder API

* `charset.h`

    Character set and encoding tables

* `error.h`

    Error table. Every Trilogy function returning an `int` uses the error codes defined here

* `packet_parser.h`

    Streaming packet frame parser

* `protocol.h`

    Low-level protocol API. Provides IO-decoupled functions to parse and build packets

* `reader.h`

    Bounds-checked packet reader API

## Bindings

We maintain a [Ruby binding](contrib/ruby) in this repository. This is currently stable and production-ready.

## License

Trilogy is released under the [MIT license](LICENSE).
