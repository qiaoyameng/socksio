# Changelog

## Unreleased

- Drop support for Python <3.10, Python 3.10 is now the minimum supported/tested version
- Add support for the SOCKS5 GSSAPI authentication method (RFC 1961). A caller-provided
  GSSAPI security context (exposing `step`, `wrap`, `unwrap` and `complete`) is injected
  into `SOCKS5Connection`; the library drives the token exchange and protection level
  negotiation and transparently wraps/unwraps the SOCKS command and application data
  when integrity or confidentiality protection is negotiated

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
