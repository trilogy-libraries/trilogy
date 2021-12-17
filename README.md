# Trilogy

Trilogy is a client library for MySQL-compatible database servers, designed for performance, flexibility, and ease of embedding.

It's currently in production use on github.com.

## Features

* Supports the most frequently used parts of the text protocol
    * Handshake
    * Password authentication
    * Query, ping, and quit commands

* Low-level protocol API completely decoupled from IO

* Non-blocking client API wrapping the protocol API

* Blocking client API wrapping the non-blocking API

* No dependencies outside of POSIX, the C standard library & OpenSSL

* Minimal dynamic allocation

* MIT licensed

## Limitations

* Only supports the parts of the text protocol that are in common use.

* No support for `LOAD DATA INFILE` on local files

* `trilogy_escape` assumes an ASCII-compatible connection encoding

## Building

`make` - that's it. This will build a static `libtrilogy.a`

Trilogy should build out of the box on most UNIX systems which have OpenSSL installed.

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
