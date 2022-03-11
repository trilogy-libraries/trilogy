# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
