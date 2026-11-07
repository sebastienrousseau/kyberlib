# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 caveat that the **patch** number is the breaking-change axis:
`0.0.x` → `0.0.(x+1)` may break source compatibility. See `SECURITY.md` for the
versioning and support policy.

## [0.0.13] - Unreleased

### Added

- **kyberlib-pkcs8** ([#168](https://github.com/sebastienrousseau/kyberlib/issues/168)):
  PKCS#8, `SubjectPublicKeyInfo` and PEM encodings for ML-KEM-512, -768
  and -1024 keys per RFC 9935. Reads all three private-key forms (seed,
  expanded, both) and writes the seed form by default. Decoding checks
  the OID, absent parameters, exact sizes, the seed/expanded consistency
  of the `both` form, an optional `publicKey`, and the FIPS 203 §7.2 /
  §7.3 checks. Keys made by OpenSSL 3.5.9 decode and re-encode byte for
  byte. Built on RustCrypto `der` 0.8, `spki` 0.8 and `pkcs8` 0.11.
  The crate stays `publish = false` until the audit (#177).
- `MlKem512EncapKey` / `MlKem768EncapKey` / `MlKem1024EncapKey::validate()`:
  the FIPS 203 §7.2 modulus check, callable at import.
- `MlKem768DecapKey::try_from_slice`: ML-KEM-768 decapsulation keys can
  now be imported from bytes (with the §7.3 hash check), like 512 and
  1024 already could.

### Changed

- The audit RFP (`doc/audits/RFP-v1.0.md`) targets v0.0.13 and adds the
  key encodings to the scope.
- CI: a `kyberlib-pkcs8 (all features)` job, and the MSRV job also
  checks kyberlib-pkcs8.

### Fixed

- `kyberlib-pkcs8` docs described a pre-standard private-key layout and
  an 11-byte OID encoding; both are corrected (the OID is 9 bytes).
- The root README's crate table described kyberlib-hybrid as
  unfinished.

## [0.0.12] - Unreleased

### Fixed

- **FIPS 203 input checks.** Encapsulation now rejects an encapsulation
  key whose coefficients are not reduced mod q (§7.2 modulus check)
  with `KyberLibError::InvalidKey`, through both the typed API and the
  legacy `encapsulate`; kyberlib 0.0.7 to 0.0.11 encapsulated to such
  keys. `MlKem512DecapKey` / `MlKem1024DecapKey::try_from_slice` now
  run the §7.3 hash check and reject mismatched keys. The UAKE/AKE
  tests that corrupted a public key now expect the rejection.
- **kyberlib-hybrid X25519MLKEM768 wire layout.** The server share is
  `ct_mlkem ‖ pk_x25519` as in draft-ietf-tls-ecdhe-mlkem; the crate
  had them reversed and could not interoperate with rustls. Both peers
  now reject an all-zero X25519 secret. (The crate is unpublished, so
  no released version is affected.)
- `examples/deterministic_seed.rs` prints the format's size constants
  rather than lengths read from the secret key (CodeQL
  `rust/cleartext-logging`).

### Added

- **`fips` feature** ([#170](https://github.com/sebastienrousseau/kyberlib/issues/170)):
  the typed ML-KEM API runs inside the AWS-LC FIPS module via
  `aws-lc-rs`, keeping the FIPS 203 encodings. `kyberlib::fips::fips_mode()`,
  `kyberlib::BACKEND` and `KyberLibError::FipsModeUnavailable` are new.
  Scope and certificate checks: `doc/FIPS.md`.
- **`KemCore::generate_from_seed(d, z)`**: FIPS 203
  `ML-KEM.KeyGen_internal` for all three parameter sets (the seed form
  of a private key).
- **kyberlib-hybrid** ([#167](https://github.com/sebastienrousseau/kyberlib/issues/167)):
  `SecP256r1MlKem768` and `SecP384r1MlKem1024` (features `secp256r1`,
  `secp384r1`) and the X-Wing KEM from
  draft-connolly-cfrg-xwing-kem-11 (feature `xwing`, default). Every TLS
  group is checked against rustls in both directions; X-Wing against
  the draft's Appendix C vectors.
- CI jobs `fips` and `hybrid-all-features`.

### Changed

- The `verified` feature is documented as a reservation (#171): still
  a no-op.

### Dependencies

- `sha3` 0.10.9 (X-Wing), `p256` / `p384` 0.14.0 and a `crypto-bigint`
  >= 0.7.6 floor (NIST-curve hybrids; RUSTSEC-2026-0387 affects
  crypto-bigint < 0.7.6), `aws-lc-rs` 1.19.0 (`fips` only).
- Minor and patch updates from Dependabot #250 and #251.
- cargo-vet: publisher trust for `cc`, `zeroize_derive` and the new
  crates above; see `supply-chain/audits.toml`.
- `deny.toml`: the OpenSSL licence is allowed for `aws-lc-fips-sys`
  only.

## [0.0.11] - 2026-10-26

### Security

- **`Debug` output no longer discloses secret material**
  ([GHSA-3g97-82p7-9p2w](https://github.com/sebastienrousseau/kyberlib/security/advisories/GHSA-3g97-82p7-9p2w)).
  Several types derived `Debug`, so formatting one with `{:?}` or
  `{:#?}` (in a log line, a panic message or `dbg!`) printed its
  secret bytes. Each now implements `Debug` by hand and prints secret
  buffers as `[REDACTED <n> bytes]` and public ones as
  `[<n> bytes; not secret]`, the format the typed ML-KEM keys already
  used:
  - `Keypair`: the secret key. Affected: kyberlib 0.0.2 to 0.0.10.
  - `Uake` and `Ake`: the shared secret, `temp_key` and the ephemeral
    secret key `eska`. Affected: kyberlib 0.0.2 to 0.0.10. Both types
    now also derive `Zeroize` and `ZeroizeOnDrop`.
  - `symmetric::KeccakState`: the sponge lanes, which hold absorbed
    input. Affected: kyberlib 0.0.4 to 0.0.10.
  - `symmetric::XofState` with the `90s` feature (`Aes256CtrCtx`): the
    expanded AES-256 key schedule. Affected: kyberlib 0.0.2 to 0.0.10.
  - `kyberlib_wasm::Keys` and `Kex`: the secret key and the shared
    secret. Affected: kyberlib-wasm 0.0.7 and 0.0.10, and the `wasm`
    module of kyberlib 0.0.2 to 0.0.6.

  kyberlib never logs these values itself; an application is exposed
  only if it formats one of them. Treat any long-term key that
  appears in existing logs as compromised and replace it.

### Fixed

- The `90s-fixslice` feature builds again. The `aes` 0.9 update had
  moved to `cipher` 0.5 while `ctr` stayed on 0.9; `ctr` is now 0.10.1
  and a new `fixslice-90s` CI job tests that feature set.

### Changed

- **The MSRV is now Rust 1.89** (was 1.74), the floor shared by the
  maintainer's Rust crates. `rust-version`, `clippy.toml`, the `msrv` CI
  job, `make msrv`, the READMEs, CONTRIBUTING.md and the audit documents
  move together. The `msrv` job no longer rewrites `Cargo.lock` to the v3
  format, and Dependabot no longer holds back `zeroize` 1.9 and
  `zeroize_derive` 1.5, both of which were there only for Rust 1.74.
- The release workflow attaches the signed artefacts to the one
  public release, titled `kyberlib <version>`, instead of opening a
  second draft release titled `v<version>`. It creates the release
  with this version's CHANGELOG section as the notes when none exists.
- `cargo vet` runs in CI and gates pull requests.
- Documentation: version and ACVP claims now read 0.0.11 and 180/180
  (60 vectors each for ML-KEM-512, -768 and -1024); the kyberlib-wasm
  README describes `wasm-pack` builds and ML-KEM-768 only, with no npm
  package; signed commits on `main` are enforced by branch protection.
- Updated dependencies: `cc` 1.8.0, `ctr` 0.10.1, `sha2` 0.11.1 (90s
  feature), `serde_json` 1.0.154, and `proptest` 1.12.0 (tests only).
  Updated GitHub Actions: `dtolnay/rust-toolchain`,
  `Swatinem/rust-cache` 2.9.3, `taiki-e/install-action` 2.87.31,
  `rust-lang/crates-io-auth-action` 1.0.6, `actions/upload-artifact`
  7.0.2, `actions/download-artifact` 8.0.2.

## [0.0.10] - 2026-10-11

### Changed

- Bumped workspace crates to version 0.0.10.
- Updated dependencies: thiserror (2.0.21), log (0.4.34), clap (4.5.32).
- Updated GitHub Actions: actions/cache (v4.3.0), actions/upload-artifact (v4.6.2), actions/download-artifact (v4.3.1), crate-ci/typos (v1.43.3).

## [0.0.9] - 2026-08-03

### Security

- Replaced the vulnerable `atty` transitive dependency used by the
  dudect benchmark harness with an MSRV-compatible compatibility crate
  backed by the sound standard-library `IsTerminal` API.
- Pinned `zeroize_derive` to 1.4.2 so the declared Rust 1.74 MSRV can
  parse and build the complete locked dependency graph.

### Changed

- Updated workspace and inter-crate versions to 0.0.9.

## [0.0.8] — 2026-07-24

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

[0.0.13]: https://github.com/sebastienrousseau/kyberlib/compare/v0.0.12...feat/v0.0.13
[0.0.12]: https://github.com/sebastienrousseau/kyberlib/compare/v0.0.11...v0.0.12
[0.0.11]: https://github.com/sebastienrousseau/kyberlib/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/sebastienrousseau/kyberlib/compare/v0.0.7...v0.0.10
