# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/minkan-chat/jose/compare/v0.0.1...v0.0.2) - 2025-04-26

### Added

- *(ci)* use cargo-nextest and release-plz in CI
- *(crypto)* implement `ring` crypto backend
- add feature flags check for crypto backends
- *(crypto)* support aws-lc via OpenSSL feature flag
- *(crypto)* support rsa key generation
- *(crypto)* implenent OpenSSL crypto backend
- *(crypto)* add dummy backend and move rustcrypto behind feature flag
- support OKP keys using abstracted crypto module
- support elliptic curves using abstracted crypto module
- support pluggable crypto backend for RSA
- expose unverifier header, payload and raw signature

### Fixed

- *(ci)* set code coverage threshold to 50%
- *(crypto)* remove `todo!()` panics
- use `try_fill_bytes` when generating random data
- use fixed size array types for hash outputs
- *(ci)* do not fail codecov ci on error
- *(crypto)* gate OpenSSL determinstic EcDSA signing behind specific version
- *(ci)* install cargo-hack in required steps
- *(ci)* adjust to new crypto backend feature flags
- hide deterministic EcDSA signing behind feature flag
- *(crypto)* dummy backend interface update
- *(crypto)* only compare public key material in `PartialEq` impls
- use custom signature type for RSA signer
- all broken doc links and remove unused dependencies
- allow `rustdoc::redudant_explicit_links` in macro

### Other

- add releaze-plz configuration with PR label
- do not ignore .envrc file
- Merge pull request #126 from minkan-chat/pluggable-crypto-backends
- *(crypto)* provide documentation for random number generation
- *(readme)* fix grammar
- *(readme)* fix typo
- Revert "fix(ci): do not fail codecov ci on error"
- *(deny)* rework deny.toml file and allow openssl licenses
- *(crypto)* always use `SecretSlice` for sensitive material
- fix broken doc links and lints in tests
- fix broken intra doc links
- start work on pluggable crypto backends
