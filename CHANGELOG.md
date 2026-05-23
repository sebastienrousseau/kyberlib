# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 caveat that the **patch** number is the breaking-change axis:
`0.0.x` → `0.0.(x+1)` may break source compatibility. See `SECURITY.md` for the
versioning and support policy.

## [Unreleased]

(Work for the next milestones lives on `feat/v0.0.8-byoe` and
`feat/v0.0.9-fips` per ADRs 0005 and 0006.)

## [0.0.7] — 2026-05-22

This release retargets kyberlib for enterprise consumption: FIPS 203
conformance, RustCrypto-style trait API, multi-crate workspace, supply-chain
hardening, and a signed release pipeline. The detailed plan lives in
[#126][i126].

### Changed

- **MSRV declared:** `rust-version = "1.74"` (was implicit edition-2018).
- **Edition bumped:** `2018` → `2021`.
- **Default features expanded:** `default = ["kyber768", "std"]`. The library
  remains `no_std`-capable via `default-features = false`. See README.
- **Crate type narrowed:** `[lib] crate-type = ["rlib"]` only. The previous
  `cdylib`/`staticlib` outputs only compiled because the non-optional
  `wasm-bindgen` dep transitively supplied a panic_handler under `no_std`.
  Making `wasm-bindgen` optional (see below) exposed the gap. A dedicated
  `kyberlib-wasm` workspace crate ([#144][i144]) restores the cdylib path.
- **`wasm-bindgen` is now optional**, gated behind the `wasm` feature.
- **`Keypair` no longer derives `Copy`.** This is a deliberate footgun fix —
  a `Copy` secret defeats `ZeroizeOnDrop` by leaving uncleared stack copies
  whenever the value was passed by value. `Zeroize` and `ZeroizeOnDrop` are
  now derived unconditionally; the `zeroize` Cargo feature is retained as a
  no-op opt-out and will be removed in a future release. See [#136][i136].
- **`Keypair::import` zeroizes the caller-supplied `secret` slice on success.**
  Public keys are not zeroized (they are not sensitive and zeroizing them
  surprised callers). Subsequent imports against the same buffer will return
  `KyberLibError::InvalidKey`; this is intentional.
- **`[package.metadata.docs.rs]` moved to the end of `Cargo.toml`.** It was
  previously *inside* the `[features]` table, orphaning `hazmat`, `90s`,
  `90s-fixslice`, `avx2`, `wasm`, `nasm`, and `std` from being recognised as
  features. The orphaning would have caused `cargo build --features 90s` etc.
  to fail at the next compiler upgrade that enforces `unexpected_cfgs`.
- **`reference::indcpa` visibility:** `pub` under `hazmat`, `pub(crate)`
  otherwise. Fixes an `E0365` re-export error surfaced by edition 2021.

### Added

- `rust-toolchain.toml` pinning `channel = "stable"` with `clippy` + `rustfmt`
  components.
- `CHANGELOG.md` (this file), Keep-a-Changelog 1.1.0 format. See [#139][i139].
- Stricter cfg checking — `[lints.rust] unexpected_cfgs` declares
  `KYBER_SECURITY_PARAMETERat`, `fuzzing`, `docsrs`, `kyber512`, `kyber1024`,
  and `benchmarking` as known cfg values.
- Crate-root `#![deny(missing_docs)]` ([#137][i137]) — every public item now
  carries rustdoc.
- `#![cfg_attr(docsrs, feature(doc_cfg))]` to render feature-gated items on
  docs.rs with their gate.

### Removed

- **Git dependency on `commons`** (`commons = { git = ..., tag = "v0.0.1" }`).
  Procurement blocker for FedRAMP / EU CRA buyers and a reproducibility hole
  (git tags can move). The dependency was already unused in `src/`. See
  [#135][i135].
- **`pqc_core` dependency.** The only consumer was a single `zero!` macro
  call in `src/api.rs`, replaced with direct `zeroize::Zeroize::zeroize`.
  See [#138][i138].
- **`rlg` dependency.** Used only by unrelated logging tests in
  `tests/test_macros.rs` that had nothing to do with kyber/ML-KEM — those
  tests were removed.
- **`tokio` dependency.** Declared as optional but never referenced in
  `src/`.
- **Duplicate `pub mod wasm;`** in `src/lib.rs` (the unconditional
  declaration pulled the WASM bindings in even when `wasm-bindgen` was
  optional).
- **Stale lints** `pointer_structural_match` and `missing_fragment_specifier`
  from `[lints.rust]` — both converted to hard errors in modern rustc.

### Fixed

- `Cargo.toml` features layout (`[package.metadata.docs.rs]` was inside the
  `[features]` table). Now `cargo build --features hazmat,90s,avx2,wasm,std`
  works as intended.
- `tests/utils/mod.rs::FailingRng::try_fill_bytes` constructed `Error::new`
  which is gated behind `rand_core`'s `std` feature. Replaced with
  `Error::from(NonZeroU32)` (no_std-safe).
- 19 missing `use rand::SeedableRng;` imports next to `use rand::rngs::StdRng;`
  in `tests/test_lib.rs` (edition 2021 stopped treating trait-method
  resolution leniently on inherent paths).
- `tests/test_wasm.rs` is now gated `#![cfg(feature = "wasm")]`; previously
  it failed to compile when the `wasm` feature was off.

### Tracking issue

- Enterprise upgrade roadmap: [#126][i126]
- Phase epics: [#127][i127] · [#128][i128] · [#129][i129] · [#130][i130] ·
  [#131][i131] · [#132][i132] · [#133][i133]

[i126]: https://github.com/sebastienrousseau/kyberlib/issues/126
[i127]: https://github.com/sebastienrousseau/kyberlib/issues/127
[i128]: https://github.com/sebastienrousseau/kyberlib/issues/128
[i129]: https://github.com/sebastienrousseau/kyberlib/issues/129
[i130]: https://github.com/sebastienrousseau/kyberlib/issues/130
[i131]: https://github.com/sebastienrousseau/kyberlib/issues/131
[i132]: https://github.com/sebastienrousseau/kyberlib/issues/132
[i133]: https://github.com/sebastienrousseau/kyberlib/issues/133
[i135]: https://github.com/sebastienrousseau/kyberlib/issues/135
[i136]: https://github.com/sebastienrousseau/kyberlib/issues/136
[i137]: https://github.com/sebastienrousseau/kyberlib/issues/137
[i138]: https://github.com/sebastienrousseau/kyberlib/issues/138
[i139]: https://github.com/sebastienrousseau/kyberlib/issues/139
[i144]: https://github.com/sebastienrousseau/kyberlib/issues/144

## [0.0.6] — 2024

Pre-enterprise-upgrade baseline. CRYSTALS-Kyber Round 3 reference + AVX2
implementations, KAT-validated, dual MIT / Apache-2.0 licensed.
