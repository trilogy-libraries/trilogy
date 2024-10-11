# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## Unreleased

## 2.9.0

### Added

- Add support for the VECTOR type. #194

### Changed
- Mark C-extension as Ractor-safe. #192

### Fixed

- Fix bug allowing queries larger than the configured `max_allowed_packet`. #203
- Restore error message context that was accidentally removed. #187

## 2.8.1

### Fixed

- Fix "Got packets out of order" errors on connect. #184

## 2.8.0

### Added

- Add support for `caching_sha2_password` when using MySQL 8.0+. #165
- Add support for `mysql_clear_password` client plugin. #171
- Add connection `#check`. #154

### Fixed

- Use `connect_timeout` for initial connection. #159

## 2.7.0

### Changed

  - `Trilogy::SyscallError::*` errors now use the standard `Module#===` implementation #143
  - `Trilogy::TimeoutError` no longer inherits from `Errno::ETIMEDOUT` #143
  - Deprecated `Trilogy::ConnectionRefusedError` and `Trilogy::ConnectionResetError`,
    replaced by `Trilogy::SyscallError::ECONNREFUSED` and `Trilogy::SyscallError::ECONNRESET` #143

## 2.6.1

### Fixed

  - Report `EOFError: TRILOGY_CLOSED_CONNECTION` for `SSL_ERROR_ZERO_RETURN`
  - `write_timeout` on connection now raises `Trilogy::TimeoutError` (previously it raised `EINPROGRESS`)
  - Fix memory leak on failed connections
  - Fix memory leak when connecting to unix socket

## 2.6.0

### Changed

  - `TCP_NODELAY` is enabled on all TCP connections #122
  - `Trilogy::EOFError` is now raised for `TRILOGY_CLOSED_CONNECTION` instead
    of the generic `Trilogy::QueryError` #118
  - `Trilogy::SyscallError` now inherits `Trilogy::ConnectionError` #118

## 2.5.0

### Fixed
  - Fix build with LibreSSL #73
  - Fix build error on FreeBSD #82
  - Fix Trilogy.new with no arguments #94
  - Fix issues with OpenSSL #95 #112
    - Avoid closing connections that are not connected
    - Always close socket on error
    - Clear error queue after close
    - Clear error queue before each operation to defend against other misbehaving libraries
  - Close connection if interrupted by a Ruby timeout #110
  - Correctly cast time of 00:00:00 #97

### Added
  - Add option to disable multi_result capability #77
  - Add option to validate max_allowed_packet #84
  - Add binary protocol/prepared statement support to the C library #3
  - Cast port option to integer #100
  - Add select_db as an alias for change_db #101

## 2.4.1

### Fixed
  - Set error code on deadlock timeout errors #69

### Changed
  - Remove superfluous `multi_result` connection option #68

## 2.4.0

### Added
  - Implement set_option functionality, and add #set_server_option method to the Ruby binding. #52
  - Implement multi-result support on the Ruby binding; TRILOGY_CAPABILITIES_MULTI_RESULTS flag enabled by default. #57
  - Add `TRILOGY_FLAGS_CAST_ALL_DECIMALS_TO_BIGDECIMALS` flag, which enforces casting to BigDecimal even for column types
    without decimal digits. #59
  - Implement #discard to close child connections without impacting parent. #65

### Fixed
  - Fix msec values for time columns. #61

### Changed
  - (BREAKING CHANGE) C API `#trilogy_build_auth_packet` accepts encoding option now. The Ruby binding for the
    Trilogy client can now accept an `:encoding` option, which will tell the connection to use the specified encoding,
    and will ensure that outgoing query strings are transcoded appropriately. If no encoding is supplied,
    utf8mb4 is used by default. #64
  - All SystemCallErrors classified as `Trilogy::Error`. #63

## 2.3.0

### Added
  - Implement multi-statement support on the Ruby binding. #35
  - Add `#connection_options` method to Ruby binding. #48
  - Introduced a variety of more detailed error classes. #15 and #41

### Changed
  - Cast to Integer rather than BigDecimal for column types without decimal digits. #37
  - Error codes 1044-1045, 1064, 1152-1161, 1205, and 1927 recategorized as `ConnectionError`. #15

## 2.2.0

### Added
  - Add `#closed?` method to Ruby binding. #30

### Changed
  - Support Ruby's `memsize` callback

### Fixed
  - Ruby: Fixed a memory leak on freed connections

## 2.1.2

2022-10-04

### Fixed

  - Don't scramble passwords when responding to auth switch request. #21
  - Allow connecting to MariaDB. #22

## 2.1.1

2022-06-06

### Fixed

  - Verify exact length of auth_data_len

## 2.1.0

2022-03-11

### Added

  - Adjust read and write timeouts after connecting. #10
  - Include `affected_rows` and `last_insert_id` on the result. #17

### Changed

  - Re-use existing interned strings where possible. #12

### Fixed

  - Clang 13 warnings. #13 and #14

## 2.0.0

2021-12-15

### Added

- Initial release of the Trilogy client.
