# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## Unreleased

### Changed
- (Breaking change) Trilogy errors all inherit from base Trilogy::Error class. #58

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
