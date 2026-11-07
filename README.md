<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!--
README template. Global rules: see ~/Code/AGENTS.md and ~/Code/REPO-STANDARD.md.
Releases adhere strictly to https://github.com/sebastienrousseau/passmcp/releases/tag/v0.0.5
-->

<p align="center">
  <img src="https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg" alt="kyberlib logo" width="128" />
</p>

<h1 align="center">kyberlib</h1>

<p align="center">
  Pure-Rust FIPS 203 ML-KEM (ML-KEM-512, -768 and -1024) post-quantum key encapsulation, checked against all 180 NIST ACVP vectors, for std, no_std and WebAssembly.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/kyberlib/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/kyberlib/ci.yml?style=for-the-badge&logo=github" alt="Build" height="28" /></a>
  <a href="https://crates.io/crates/kyberlib"><img src="https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Registry" height="28" /></a>
  <a href="https://docs.rs/kyberlib"><img src="https://img.shields.io/docsrs/kyberlib?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs" height="28" /></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/sebastienrousseau/kyberlib"><img src="https://img.shields.io/ossf-scorecard/github.com/sebastienrousseau/kyberlib?style=for-the-badge&label=OpenSSF%20Scorecard&logo=openssf" alt="OpenSSF Scorecard" height="28" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg?style=for-the-badge" alt="License: Apache-2.0 OR MIT" height="28" /></a>
  <a href="https://github.com/sebastienrousseau/kyberlib/blob/main/docs/POLICIES.md"><img src="https://img.shields.io/badge/MSRV-1.89-93450a.svg?style=for-the-badge&logo=rust" alt="Minimum Rust version: 1.89" height="28" /></a>
</p>

<p align="center">
  <img src=".github/demo.gif" alt="A terminal running cargo run --example typed_kem, which establishes a 32-byte ML-KEM-768 shared secret, then make acvp, which passes all 180 NIST ACVP vectors for ML-KEM-512, -768 and -1024" width="100%" />
</p>

---

## Contents

**Getting started**

- [Install](#install) — crates.io, no_std, WebAssembly, from source, verified release artefacts
- [Requirements](#requirements) — toolchain floor, platforms
- [Quick Start](#quick-start) — one ML-KEM-768 key agreement in a dozen lines

**The kyberlib ecosystem**

- [The kyberlib ecosystem](#the-kyberlib-ecosystem) — `kyberlib`, `kyberlib-hybrid`, `kyberlib-pkcs8`, `kyberlib-wasm`

**Library reference**

- [Capabilities at a glance](#capabilities-at-a-glance) — the current surface by theme
- [Ecosystem comparison](#ecosystem-comparison) — short matrix; full table at [`docs/COMPARISON.md`](docs/COMPARISON.md)
- [Benchmarks](#benchmarks) — headline numbers; full table at [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
- [Features](#features) — module-level capability list
- [Configuration](#configuration) — core options
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use kyberlib](#when-not-to-use-kyberlib) — limitations
- [Development](#development) — make targets, fuzzing, CI
- [Security](#security) — guarantees and compliance
- [Documentation](#documentation) — all reference docs
- [Stability guarantees](#stability-guarantees) — SemVer axis, output stability, minimum toolchain discipline
- [License](#license)

---

## Install

### As a Rust library

```toml
[dependencies]
kyberlib = "0.0.16"
```

Or `cargo add kyberlib`.

**`no_std`.** Turn off the default `std` feature and keep the default
parameter-set feature. An allocator is required.

```toml
[dependencies]
kyberlib = { version = "0.0.16", default-features = false, features = ["kyber768"] }
```

**WebAssembly.** The core crate builds for `wasm32-unknown-unknown`; for
JavaScript bindings use [`kyberlib-wasm`](crates/kyberlib-wasm/README.md)
and build it with `wasm-pack build crates/kyberlib-wasm --release --target web`
(there is no npm package).

**From source.**

```bash
git clone https://github.com/sebastienrousseau/kyberlib.git
cd kyberlib
make ci
```

**Verified release artefacts.** Each GitHub release attaches the `.crate`
file with a keyless cosign bundle, SLSA build provenance, a CycloneDX
cryptography bill of materials and checksums; see [Security](#security)
for the verification commands.

---

## Requirements

- **Rust 1.89 or newer** (the declared minimum, checked in CI; policy in
  [`docs/POLICIES.md`](docs/POLICIES.md)).
- Linux, macOS or Windows on x86_64 or aarch64, or any target with an
  allocator for `no_std` builds.
- **Randomness from the caller.** Every key generation and encapsulation
  takes `&mut R` where `R: rand_core::RngCore + rand_core::CryptoRng`. On
  hosted platforms pass `rand::rngs::OsRng`; on bare metal pass a vetted
  hardware RNG. The library never looks for randomness on its own.
- The `fips` feature additionally needs CMake, Go and a C compiler to build
  the AWS-LC FIPS module.

---

## Quick Start

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    // The receiver generates a key pair. `dk` is !Copy and zeroized on drop.
    let (dk, ek) = MlKem768::generate(&mut rng)?;

    // The sender encapsulates to the public key `ek`.
    let (ct, ss_sender) = ek.encapsulate(&mut rng)?;

    // The receiver decapsulates. Implicit rejection (FIPS 203 §6.3):
    // a tampered ciphertext yields an unrelated secret, never a panic.
    let ss_receiver = dk.decapsulate(&ct);

    assert_eq!(ss_sender, ss_receiver);
    Ok(())
}
```

The 32-byte shared secret is a key for a symmetric cipher such as an AEAD.
`MlKem512` and `MlKem1024` work the same way.

---

## The kyberlib ecosystem

The workspace ships four crates at one shared version. `kyberlib` and
`kyberlib-wasm` are published on crates.io; the others stay unpublished
until the third-party audit.

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| [`kyberlib`](crates/kyberlib/README.md) | FIPS 203 ML-KEM-512/768/1024; typed `KemCore` API and legacy byte-array functions; optional `fips` backend | Any Rust program that needs post-quantum key exchange |
| [`kyberlib-hybrid`](crates/kyberlib-hybrid/README.md) | TLS 1.3 hybrid groups X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 (`draft-ietf-tls-ecdhe-mlkem-05`) and the X-Wing KEM (`draft-connolly-cfrg-xwing-kem-11`); unpublished | TLS stacks; HPKE-style protocols that need one 32-byte hybrid secret |
| [`kyberlib-pkcs8`](crates/kyberlib-pkcs8/README.md) | PKCS#8, SubjectPublicKeyInfo and PEM per RFC 9935, including password-encrypted PKCS#8; unpublished | Key files that OpenSSL 3.5 reads and writes |
| [`kyberlib-wasm`](crates/kyberlib-wasm/README.md) | `wasm-bindgen` bindings for ML-KEM-768 | Browsers, Node.js, Deno, Cloudflare Workers |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| Standard | FIPS 203 ML-KEM-512, -768 and -1024 key generation, encapsulation, decapsulation | ✓ 180/180 NIST ACVP vectors |
| Standard | Input checks: encapsulation-key modulus check (§7.2), decapsulation-key hash check (§7.3) | ✓ |
| API | Typed `KemCore` API with separate key types; seeded key generation (`generate_from_seed`) | ✓ |
| API | Legacy byte-array functions (`keypair`, `encapsulate`, `decapsulate`) | ✓ soft-deprecated |
| Secret hygiene | Secret keys `!Copy`, zeroized on drop, redacted `Debug` | ✓ |
| Side channels | KyberSlash-clean arithmetic, enforced by a CI guard | ✓ ([ADR 0003](docs/adr/0003-kyberslash-audit.md)) |
| Targets | `no_std` with an allocator; `wasm32` | ✓ |
| Backends | AWS-LC FIPS module via `aws-lc-rs` (`fips` feature) | ✓ ([`docs/FIPS.md`](docs/FIPS.md)) |
| Backends | libcrux (`verified`), bringing AVX2 and NEON | planned ([#171](https://github.com/sebastienrousseau/kyberlib/issues/171), [#172](https://github.com/sebastienrousseau/kyberlib/issues/172)); the never-working in-tree AVX2 code was removed ([ADR 0009](docs/adr/0009-remove-avx2-backend.md)) |
| Hybrids | Three TLS groups and X-Wing, checked against rustls and the draft's vectors | ✓ in `kyberlib-hybrid` |
| Key files | RFC 9935 PKCS#8 / SPKI / PEM, encrypted PKCS#8, byte-for-byte with OpenSSL 3.5 | ✓ in `kyberlib-pkcs8` |
| Releases | SLSA build provenance, keyless cosign signature, CycloneDX 1.6 CBOM | ✓ |
| Audit | Third-party security audit | not started ([RFP](docs/audits/RFP-v1.0.md)) |

---

## Ecosystem comparison

Other Rust options for ML-KEM, on three facts that decide most choices.
[`docs/COMPARISON.md`](docs/COMPARISON.md) has the longer matrix.

| Project | Standard | Implementation | Route to a FIPS 140-3 module |
| :--- | :---: | :---: | :---: |
| **kyberlib** | FIPS 203 | Rust | `fips` feature (AWS-LC) |
| `ml-kem` (RustCrypto) | FIPS 203 | Rust | — |
| `libcrux-ml-kem` | FIPS 203 | Rust, verified with F\* and hax | — |
| `aws-lc-rs` | FIPS 203 | C (AWS-LC) through FFI | AWS-LC FIPS module |
| `oqs` (liboqs) | FIPS 203 | C through FFI | — |
| `pqcrypto-kyber` | CRYSTALS-Kyber Round 3 | C through FFI | — |

See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the evidence and complete matrix.

---

## Benchmarks

Mean time per operation for ML-KEM-768, from Criterion in quick mode.
These are the figures recorded in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md);
they were measured on kyberlib 0.0.7 and have not been re-measured since.

| Scenario | Result | Environment |
| :--- | ---: | :--- |
| Key generation (typed API) | 22.91 µs | Apple M1 Pro, macOS 26.5, rustc 1.95.0, kyberlib 0.0.7, pure Rust |
| Encapsulation (typed API) | 20.91 µs | same |
| Decapsulation (typed API) | 19.93 µs | same |
| Full handshake (generate, encapsulate, decapsulate) | 66.99 µs | same |

See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for methodology and full results.

---

## Features

**Two APIs over the same primitives.**

| Action | Typed `KemCore` (preferred) | Legacy free functions |
| :--- | :--- | :--- |
| Generate a key pair | `MlKem768::generate(&mut rng)?` | `kyberlib::keypair(&mut rng)?` |
| Encapsulate | `ek.encapsulate(&mut rng)?` | `kyberlib::encapsulate(&pk, &mut rng)?` |
| Decapsulate | `dk.decapsulate(&ct)` (no `Result`) | `kyberlib::decapsulate(&ct, &sk)?` |
| Secret type | `MlKem768DecapKey` (`!Copy`, redacted `Debug`) | `Keypair { public, secret }` |

The typed API keeps secret hygiene in the types; the legacy functions take
and return byte arrays and leave that to the caller.

**Conformance.** Byte-for-byte NIST ACVP agreement for all three parameter
sets (`crates/kyberlib/tests/test_acvp.rs`). Imported keys are checked:
`MlKem*EncapKey::validate()` and `MlKem*DecapKey::try_from_slice()` run
the FIPS 203 §7.2 and §7.3 checks, and encapsulation always runs §7.2.

**Implicit rejection.** `decapsulate` never panics and never branches on
ciphertext validity; a tampered ciphertext gives `J(z‖c)`.

**No `unsafe`.** The core crate is `#![forbid(unsafe_code)]` in every
build.

**Constant time.** Arithmetic on secrets uses Barrett multiply-and-shift,
never `/` or `%` against `KYBER_Q`; `scripts/kyberslash-guard.sh` fails CI
on a new occurrence. The dudect harness (`cargo xtask dudect`) tests
decapsulation timing.

**Memory hygiene.** Secret keys and shared secrets are zeroized on drop
and print as `[REDACTED <n> bytes]`. Public types derive `Copy`.

**Hazardous APIs.** The `hazmat` feature exposes the IND-CPA primitives and
the `Uake` / `Ake` key exchanges (`kyberlib::hazmat::kex`), which have only
implicit authentication ([ADR 0008](docs/adr/0008-kex-to-hazmat.md)).

---

## Configuration

kyberlib is configured through Cargo features. All are off unless marked
default.

| Feature | Default | Effect |
| :--- | :---: | :--- |
| `std` | ✓ | `std::error::Error` for `KyberLibError` |
| `kyber768` | ✓ | ML-KEM-768 for the legacy functions; the typed API has all three sets in every build |
| `kyber512`, `kyber1024` | | ML-KEM-512 / -1024 for the legacy functions |
| `fips` | | Typed API runs inside the AWS-LC FIPS module ([`docs/FIPS.md`](docs/FIPS.md)) |
| `hazmat` | | IND-CPA primitives and `hazmat::kex::{Uake, Ake}` |
| `90s`, `90s-fixslice` | | CRYSTALS-Kyber "90s" variant (AES/SHA-2); not in FIPS 203 |
| `verified` | | No-op; reserved for a libcrux backend ([#171](https://github.com/sebastienrousseau/kyberlib/issues/171)) |
| `wasm`, `zeroize` | | No-ops kept for compatibility with 0.0.6 |

```toml
# Run ML-KEM inside the AWS-LC FIPS module.
[dependencies]
kyberlib = { version = "0.0.16", features = ["fips"] }
```

---

## Examples

From the repository root:

| Command | What it shows |
| :--- | :--- |
| `cargo run -p kyberlib --example typed_kem` | ML-KEM-768 round trip with the typed API |
| `cargo run -p kyberlib --example kem` | The same with the legacy byte-array functions |
| `cargo run -p kyberlib --example deterministic_seed` | Key generation from a fixed seed |
| `cargo run -p kyberlib --example uake --features hazmat` | `Uake` key exchange |
| `cargo run -p kyberlib --example ake --features hazmat` | `Ake` key exchange |
| `cargo run -p kyberlib-pkcs8 --example pem_roundtrip --features pem,std` | Write and read an ML-KEM key as PEM |

---

## When not to use kyberlib

- **You need an audited library today.** No third-party audit has been
  done; the RFP is ready ([`docs/audits/RFP-v1.0.md`](docs/audits/RFP-v1.0.md))
  and `v1.0.0` will not ship without one.
- **You need a certified module and cannot check coverage yourself.** The
  `fips` feature runs ML-KEM inside the AWS-LC FIPS module, but kyberlib
  holds no certificate ([ADR 0007](docs/adr/0007-no-cmvp-submission.md));
  coverage depends on the AWS-LC version and your environment.
- **You need SIMD speed today.** kyberlib is pure Rust; SIMD arrives with
  the libcrux backend ([#171](https://github.com/sebastienrousseau/kyberlib/issues/171)).
- **You want the hybrid or key-file crates from crates.io.** They are
  unpublished until the audit; use them as git or path dependencies.
- **You want a command-line tool.** kyberlib is a library.

---

## Development

```bash
make ci                    # fmt, clippy, strict docs, tests, deny, machete, guards, REUSE
make acvp                  # NIST ACVP vectors, all three parameter sets
make test-no-std           # the core crate without std
make miri                  # focused Miri run (nightly); make miri-full for everything
make fuzz-smoke            # 10-second cargo-fuzz run of fuzz_decap
make kyberslash-guard      # no `/` or `%` against KYBER_Q in sources
make non-exhaustive-guard  # every public type is #[non_exhaustive]
make demo                  # re-render .github/demo.gif (needs vhs)
```

`make help` lists every target. CI runs the same checks on Linux, macOS
and Windows, plus jobs for MSRV, Miri, fuzzing, coverage, cargo-vet,
cargo-semver-checks, the `fips`, `hazmat`, hybrid and PKCS#8 feature
sets, and an offline vendored build. Contributions follow
[`CONTRIBUTING.md`](CONTRIBUTING.md): signed, signed-off commits and an
ADR for decisions that change the API, conformance or security posture.

---

## Security

**Threat model.** In scope: decapsulation oracles, timing side channels
on secret data, leaks of secret material, panics on malformed input.
Out of scope: physical attacks (power, EM, fault injection), a compromised
OS or RNG. Details and per-function constant-time claims are in
[`SECURITY.md`](SECURITY.md).

**Supply chain.** cargo-deny and cargo-vet gate every pull request
(cargo-vet imports audits from Mozilla, Google, the Bytecode Alliance,
Embark, Fermyon, ISRG and Zcash); every GitHub Action is pinned to a
commit; `Cargo.lock` is committed and CI builds `--locked`; commits on
`main` must be signed.

**Verifying a release.**

```bash
gh release download v0.0.16 -R sebastienrousseau/kyberlib \
  --pattern 'kyberlib-0.0.16.crate*' --pattern SHA256SUMS
gh attestation verify --owner sebastienrousseau kyberlib-0.0.16.crate
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/sebastienrousseau/kyberlib/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle kyberlib-0.0.16.crate.cosign-bundle.json kyberlib-0.0.16.crate
shasum -a 256 --ignore-missing -c SHA256SUMS
```

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

---

## Documentation

| Document | Contents |
| :--- | :--- |
| [docs.rs/kyberlib](https://docs.rs/kyberlib) | API reference |
| [`docs/kyberlib/cookbook.md`](docs/kyberlib/cookbook.md) | Recipes: AEAD, serialisation, no_std, key exchanges |
| [`docs/MIGRATION.md`](docs/MIGRATION.md) | Moving from kyberlib 0.0.6, `pqcrypto-kyber`, `ml-kem`, `libcrux-ml-kem` or `oqs` |
| [`docs/FIPS.md`](docs/FIPS.md) | The `fips` backend and certificate coverage |
| [`docs/POLICIES.md`](docs/POLICIES.md) | Versioning, MSRV and stability policy |
| [`docs/COMPARISON.md`](docs/COMPARISON.md), [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Comparison with other crates; benchmark method and results |
| [`docs/adr/`](docs/adr/) | Architecture decision records |
| [`docs/audits/`](docs/audits/), [`docs/RELEASE-1.0-CHECKLIST.md`](docs/RELEASE-1.0-CHECKLIST.md) | Audit RFP and materials; the v1.0.0 bar |
| [`CHANGELOG.md`](CHANGELOG.md), [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md) | Release history, security policy, contributing |

Per-crate documents live under `docs/<crate>/`.

---

## Stability guarantees

- **SemVer axis.** kyberlib is `0.0.x`: the patch number is the breaking
  axis, and each release's CHANGELOG section says what broke. Versions go
  up by `0.0.1`; `v1.0.0` freezes the API once
  [`docs/RELEASE-1.0-CHECKLIST.md`](docs/RELEASE-1.0-CHECKLIST.md) is met.
- **Output stability.** Keys, ciphertexts and shared secrets follow
  FIPS 203 byte for byte, and key files follow RFC 9935. Changing those
  bytes is a breaking change even when no signature moves. The hybrid wire
  format follows the drafts named above; a new draft revision that changes
  bytes ships as a breaking release that names it.
- **Minimum toolchain.** Rust 1.89, checked in CI. Raising it is allowed
  in any release and is recorded, with the reason, in the CHANGELOG.

Full policy: [`docs/POLICIES.md`](docs/POLICIES.md).

---

## License

Dual-licensed under either of

- [Apache License 2.0](LICENSE-APACHE) (`Apache-2.0`)
- [MIT License](LICENSE-MIT) (`MIT`)

at your option (SPDX expression `Apache-2.0 OR MIT`). Unless you
state otherwise, any contribution you submit for inclusion is licensed as
above, without additional terms.
