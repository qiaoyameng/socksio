# Changelog

## Unreleased

- Drop support for Python <3.10, Python 3.10 is now the minimum supported/tested version
- Added the full two-reply BIND state machine to `SOCKS4Connection` and
  `SOCKS5Connection`. The first successful reply produces a listening-address
  event without entering the tunnel state; the second reply signals the
  connected peer. Partial replies are buffered so data can be fed one byte at
  a time, tunnel data arriving with the final reply is exposed via
  `Connection.tunnel_data()`, failures move the connection to a terminal
  state, and new commands are rejected while a BIND reply is pending.

## 1.0.0 (2020-04-17)

### Changed

- `from_address` methods now accept `str` or `bytes` objects
[#46](https://github.com/sethmlarson/socksio/pull/46).

## 0.2.0 (2020-01-28)

### Changed

- **BREAKING**: API redesign using request objects and reducing the methods in
the different connection classes [#37](https://github.com/sethmlarson/socksio/pull/37).

## 0.1.1 (2020-01-10)

### Fixed

- SOCKS5 prefixing domain name with length [#29](https://github.com/sethmlarson/socksio/pull/29).
- SOCKS5 requiring authentication even if no authentication method is specified
[#30](https://github.com/sethmlarson/socksio/pull/30).

## 0.1.0 (2019-12-03)

Initial release.
