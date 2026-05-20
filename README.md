<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg" alt="kyberlib logo" width="128" />
</p>

<h1 align="center">kyberlib</h1>

<p align="center">
  A pure-Rust FIPS 203 ML-KEM (post-quantum key-encapsulation)
  library — ACVP-conformant for ML-KEM-768, hybrid-ready, audited
  against KyberSlash, with a SLSA L3 + cosign signed release
  pipeline.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/kyberlib/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/kyberlib/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/kyberlib"><img src="https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/kyberlib"><img src="https://img.shields.io/badge/docs.rs-kyberlib-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://lib.rs/crates/kyberlib"><img src="https://img.shields.io/badge/lib.rs-kyberlib-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
  <a href="https://codecov.io/gh/sebastienrousseau/kyberlib"><img src="https://img.shields.io/codecov/c/github/sebastienrousseau/kyberlib?style=for-the-badge&logo=codecov" alt="Coverage" /></a>
  <a href="https://api.securityscorecards.dev/projects/github.com/sebastienrousseau/kyberlib"><img src="https://api.securityscorecards.dev/projects/github.com/sebastienrousseau/kyberlib/badge" alt="OpenSSF Scorecard" /></a>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge" alt="License" /></a>
  <a href="https://github.com/sebastienrousseau/kyberlib/blob/main/doc/adr/0001-fips203-migration.md"><img src="https://img.shields.io/badge/FIPS_203-ML--KEM--768_ACVP_60%2F60-success?style=for-the-badge" alt="FIPS 203 conformance" /></a>
</p>

---

## Contents

**Getting started**

- [Install](#install) — Cargo, source, WASM, `no_std`
- [Quick Start](#quick-start) — typed `KemCore` API in ten lines

- [The kyberlib ecosystem](#the-kyberlib-ecosystem) — `kyberlib`, `kyberlib-asm`, `kyberlib-hybrid`, `kyberlib-pkcs8`, `kyberlib-wasm` at a glance

**Library reference**

- [Migrating to FIPS 203 ML-KEM](#migrating-to-fips-203-ml-kem) — `diff`-style snippets from `pqcrypto-kyber`, `RustCrypto/ml-kem`, `libcrux-ml-kem`, `oqs-rs`, and the legacy kyberlib 0.0.6 surface
- [Why this approach?](#why-this-approach) — design rationale
- [Capabilities in 0.0.7](#capabilities-in-007) — release inventory
- [Two APIs, one KEM](#two-apis-one-kem) — legacy free functions vs. type-state `KemCore`
- [Ecosystem comparison](#ecosystem-comparison) — short matrix; full table at [`doc/COMPARISON.md`](doc/COMPARISON.md)
- [Benchmarks](#benchmarks) — headline numbers; full table at [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md)
- [Features](#features) — Cargo-feature capability list
- [Library usage](#library-usage) — keygen, encapsulate, decapsulate, hybrid
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use kyberlib](#when-not-to-use-kyberlib) — limitations
- [Development](#development) — make targets, fuzzing, Miri, dudect, ACVP
- [Security](#security) — threat model, CT guarantees, audit posture
- [Release artefacts](#release-artefacts) — SLSA L3 + cosign + CBOM verification
- [Documentation](#documentation) — all reference docs
- [License](#license)

---

## Install

### As a Rust library (crates.io)

```toml
[dependencies]
kyberlib = "0.0.7"
```

You need [Rust](https://rustup.rs/) stable ≥ 1.74 (the declared MSRV).
Works on Linux, macOS, and Windows on x86_64 and aarch64.

### Channels

kyberlib doesn't ship a standalone binary — it's a library — so
the per-OS package-manager matrix is narrower than a CLI's. The
satellite crates each have their own channels (see
[The kyberlib ecosystem](#the-kyberlib-ecosystem)).

| Channel | Install |
|---|---|
| Cargo (crates.io) | `cargo add kyberlib` |
| Cargo (from source) | `cargo install --locked --path crates/kyberlib` |
| WASM bundle (npm) | `npm install @kyberlib/kyberlib-wasm` *(coming with v0.0.7 release)* |
| Pre-built `.crate` (GitHub Releases) | `gh release download v0.0.7 --pattern 'kyberlib-*.crate'` |
| Verified `.crate` (cosign + SLSA L3) | see [Release artefacts](#release-artefacts) |

### `no_std` support

```toml
[dependencies]
kyberlib = { version = "0.0.7", default-features = false, features = ["kyber768"] }
```

Requires `alloc` (because of `Vec` buffers in the rejection sampler).
The safe core compiles for `wasm32-unknown-unknown`, embedded
ARM targets, and any other `alloc`-capable, no-`std` host. Enabling
`std` adds `std::error::Error` impls and the `getrandom`-backed
default RNG.

**Bring your own RNG.** Every keygen / encapsulate entry point takes
an `&mut R` where `R: rand_core::CryptoRng + rand_core::RngCore`.
On embedded targets you'd typically pass a hardware-RNG wrapper:

```rust,ignore
use kyberlib::{KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};

// `MyHwRng` is your platform's CSPRNG wrapper — e.g. `embedded-hal`'s
// `rand_core` impl over an STM32 / nRF / RP2040 TRNG peripheral.
fn handshake<R: CryptoRng + RngCore>(rng: &mut R)
    -> Result<(), kyberlib::KyberLibError>
{
    let (dk, ek) = MlKem768::generate(rng)?;
    let (ct, ss_a) = ek.encapsulate(rng)?;
    let ss_b = dk.decapsulate(&ct);
    debug_assert_eq!(ss_a, ss_b);
    Ok(())
}
```

A user-supplied `rand_core::OsRng` works on most hosted platforms;
on bare metal, plug a vetted TRNG. The library never reaches for
`std::*` to find randomness — the caller is always in control.

### Build from source

```bash
git clone https://github.com/sebastienrousseau/kyberlib.git
cd kyberlib
make ci          # fmt + clippy + doc + test + deny + machete + kyberslash-guard
```

### MSRV

The declared MSRV is **Rust 1.74** for the core (`crates/kyberlib`).
A dedicated `msrv` CI job gates this on every PR. Satellite crates
inherit the same floor.

### Cargo features

All non-essential features are opt-in. Enable only what your
application needs.

| Feature | Default? | Pulls in | Adds | Documented in |
|---|---|---|---|---|
| `kyber768`         | ✓ | — | ML-KEM-768 parameter set (the only `KemCore` impl today) | [Capabilities](#capabilities-in-007) |
| `std`              | ✓ | — | `std::error::Error` impl; opt-in `getrandom` plumbing | [Install](#install) |
| `hazmat`           |   | — | IND-CPA primitives — bypasses the FO transform; use with care | [docs.rs `reference::indcpa`](https://docs.rs/kyberlib) |
| `90s`              |   | `sha2` | AES-CTR + SHA-2 instead of SHAKE (Kyber-R3 era; removed from FIPS 203) | CHANGELOG |
| `90s-fixslice`     |   | `aes`, `ctr` | Bitsliced AES for side-channel hardening of 90s mode | CHANGELOG |
| `avx2`             |   | `cc` | x86_64 SIMD acceleration of the polynomial arithmetic | [`crates/kyberlib-asm/`](crates/kyberlib-asm/) |
| `nasm`             |   | `nasm-rs`, `avx2` | NASM-assembled AVX2 (portable to non-GAS toolchains) | [`crates/kyberlib-asm/`](crates/kyberlib-asm/) |
| `wasm`             |   | — | **Legacy / Compat (no-op):** retained for v0.0.6 downstream compatibility — real WASM bindings live in [`kyberlib-wasm`](crates/kyberlib-wasm/). Do not enable. | CHANGELOG |
| `zeroize`          |   | — | **Legacy / Compat (no-op):** retained for v0.0.6 backwards compatibility — `ZeroizeOnDrop` is unconditional since v0.0.7. Do not enable. | CHANGELOG |
| `fips`             |   | (stub) | Planned `aws-lc-rs` delegation for FIPS 140-3 customers — issue [#170](https://github.com/sebastienrousseau/kyberlib/issues/170) | [SECURITY](SECURITY.md) |
| `verified`         |   | (stub) | Planned `libcrux-ml-kem` delegation for formally-verified primitives — issue [#171](https://github.com/sebastienrousseau/kyberlib/issues/171) | [SECURITY](SECURITY.md) |

```toml
# Example: production server with x86_64 SIMD acceleration
[dependencies]
kyberlib = { version = "0.0.7", features = ["avx2"] }
```

---

## Quick Start

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    // (1) Generate a key pair. `dk` is `!Copy` + ZeroizeOnDrop.
    let (dk, ek) = MlKem768::generate(&mut rng)?;

    // (2) Sender encapsulates against the public key.
    let (ct, ss_sender) = ek.encapsulate(&mut rng)?;

    // (3) Receiver decapsulates. Implicit rejection per FIPS 203 §6.3:
    //     never panics, never branches on validity.
    let ss_receiver = dk.decapsulate(&ct);

    assert_eq!(ss_sender, ss_receiver);
    Ok(())
}
```

For the legacy free-function surface (`keypair` / `encapsulate` /
`decapsulate`), see [Two APIs, one KEM](#two-apis-one-kem).

---

## The kyberlib ecosystem

Five crates ship from this workspace. The core library is `kyberlib`;
the four satellites quarantine `unsafe`, add the TLS hybrid surface,
expose PKCS#8 / SPKI encoding, and wrap the library for the browser.

| Crate | What it is | Status (v0.0.7) | Use case |
|---|---|---|---|
| **[`kyberlib`](crates/kyberlib/)** | Core library — FIPS 203 ML-KEM, no_std + alloc, `#![forbid(unsafe_code)]` (default features) | Published; ACVP 60/60 on ML-KEM-768 | Embed ML-KEM in any Rust binary or library. |
| **[`kyberlib-asm`](crates/kyberlib-asm/)** | AVX2 / NEON / SIMD acceleration backend (planned relocation of `crates/kyberlib/src/avx2/`) | Skeleton — see [ADR 0002](doc/adr/0002-asm-quarantine.md) and issue [#143](https://github.com/sebastienrousseau/kyberlib/issues/143) | High-throughput servers; embedded NEON targets. |
| **[`kyberlib-hybrid`](crates/kyberlib-hybrid/)** | TLS 1.3 hybrid KEMs — X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | `X25519MlKem768` wired; ECDHE variants in [#167b](https://github.com/sebastienrousseau/kyberlib/issues/167) | Direct interop with `draft-ietf-tls-ecdhe-mlkem-04`. |
| **[`kyberlib-pkcs8`](crates/kyberlib-pkcs8/)** | PKCS#8 / `SubjectPublicKeyInfo` / PEM encoding with LAMPS-registered OIDs | Skeleton — issue [#168](https://github.com/sebastienrousseau/kyberlib/issues/168) | X.509 cert chains, CMS, PEM exchange. |
| **[`kyberlib-wasm`](crates/kyberlib-wasm/)** | `wasm-bindgen` wrapper for browser / Node / Cloudflare Workers / Deno | Published with `kyberlib` | Browser cryptography; npm-installable. |

Per-crate READMEs cover the surface specific to each artifact:

- **ASM**: [`crates/kyberlib-asm/README.md`](crates/kyberlib-asm/README.md)
- **Hybrid**: [`crates/kyberlib-hybrid/README.md`](crates/kyberlib-hybrid/README.md) — wire-format constants, codepoints
- **PKCS#8**: [`crates/kyberlib-pkcs8/README.md`](crates/kyberlib-pkcs8/README.md) — OID table, encoding traits
- **WASM**: [`crates/kyberlib-wasm/README.md`](crates/kyberlib-wasm/README.md) — JS API, bundling

#### `kyberlib-hybrid` versioning policy

The IETF PQC draft landscape moves fast. `kyberlib-hybrid` pins its
wire format and codepoints to a specific draft, and bumps SemVer on
that schedule:

| Draft transition | SemVer bump | Why |
|---|---|---|
| `draft-04` → `draft-05`+ (same IETF working draft) | **MINOR** (0.0.x → 0.1.0) | Codepoints stable; wire-format tweaks may break interop, but the type-level API stays. |
| Working draft → final RFC | **MAJOR** (0.x → 1.0) | IANA-permanent codepoints; we commit to the API contract. |
| Codepoint reassignment by IANA | **MAJOR** | Breaking by definition. |
| New construction added (e.g. ML-KEM + Ed25519) | **MINOR** | Additive. |

The current pin is `draft-ietf-tls-ecdhe-mlkem-04`. CHANGELOG entries
on `kyberlib-hybrid` always cite the active draft revision so
downstream consumers can audit the wire-format ancestry.

The rest of this README covers the **library** surface
(`kyberlib` itself).

---

## Migrating to FIPS 203 ML-KEM

kyberlib v0.0.7 implements **FIPS 203 ML-KEM** (NIST, August 2024)
— the standardised form of CRYSTALS-Kyber Round 3. v0.0.6 and
earlier shipped the Round-3 surface. The byte-level deltas
(K-byte domain separator, dropped `m' = H(m)` pre-hash, dropped
final KDF + `J(z‖c)` rejection branch) are documented in
[ADR 0001](doc/adr/0001-fips203-migration.md). Three concrete
migration paths:

### From kyberlib 0.0.6 → 0.0.7

> ⚠️ **Persisted v0.0.6 key material will NOT seamlessly drop in to v0.0.7.**
> Round 3 and FIPS 203 differ in the keygen domain separator, the
> encaps pre-hash, and the rejection KDF — so 0.0.6 secret keys,
> ciphertexts, and shared secrets are wire-incompatible with 0.0.7.
> You **must regenerate keys** on both peers in lockstep.

```diff
-[dependencies]
-kyberlib = "0.0.6"
+[dependencies]
+kyberlib = "0.0.7"
```

```diff
-let keys = kyberlib::keypair(&mut rng)?;
-let (ct, ss_a) = kyberlib::encapsulate(&keys.public, &mut rng)?;
-let ss_b = kyberlib::decapsulate(&ct, &keys.secret)?;
+let (dk, ek) = kyberlib::MlKem768::generate(&mut rng)?;     // typed
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);                              // no Result
```

The free-function surface (`keypair` / `encapsulate` / `decapsulate`)
still works — it's soft-deprecated and delegates to the typed API.
Shared-secret bytes change vs. 0.0.6 because of the FIPS 203
spec migration; this is **intentional** and required for interop
with every other FIPS 203 endpoint.

### From `pqcrypto-kyber`

```diff
-[dependencies]
-pqcrypto-kyber = "0.8"
+[dependencies]
+kyberlib = "0.0.7"
```

```diff
-use pqcrypto_kyber::kyber768::{keypair, encapsulate, decapsulate};
-let (pk, sk) = keypair();
-let (ss_a, ct) = encapsulate(&pk);
-let ss_b = decapsulate(&ct, &sk);
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);
```

`pqcrypto-kyber` is Round-3 and marked unmaintained. Shared
secrets, ciphertexts, and public keys are byte-incompatible with
FIPS 203. Migrating requires re-generating any persisted
key material.

### From `RustCrypto/ml-kem`

```diff
-[dependencies]
-ml-kem = "0.3"
+[dependencies]
+kyberlib = "0.0.7"
```

```diff
-use ml_kem::{MlKem768, KemCore};
-use ml_kem::kem::{Encapsulate, Decapsulate};
-let (dk, ek) = MlKem768::generate(&mut rng);
-let (ct, k_sender) = ek.encapsulate(&mut rng).unwrap();
-let k_receiver = dk.decapsulate(&ct).unwrap();
+use kyberlib::{MlKem768, KemCore};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, k_sender) = ek.encapsulate(&mut rng)?;
+let k_receiver = dk.decapsulate(&ct);  // no Result — implicit rejection
```

API shapes are deliberately convergent. Notable behavioural
differences listed in [`doc/COMPARISON.md`](doc/COMPARISON.md).

### From `libcrux-ml-kem`

```diff
-[dependencies]
-libcrux-ml-kem = "0.0"
+[dependencies]
+kyberlib = "0.0.7"
```

Function-name table:

| `libcrux-ml-kem` | `kyberlib` |
|---|---|
| `libcrux_ml_kem::mlkem768::generate_key_pair_unpacked(seed)` | `MlKem768::generate(&mut rng)` |
| `libcrux_ml_kem::mlkem768::encapsulate(ek, randomness)` | `ek.encapsulate(&mut rng)` |
| `libcrux_ml_kem::mlkem768::decapsulate(dk, ct)` | `dk.decapsulate(&ct)` |
| (`MlKemPublicKey<{1184}>`) | `MlKem768EncapKey` |
| (`MlKemPrivateKey<{2400}>`) | `MlKem768DecapKey` |
| (`MlKemCiphertext<{1088}>`) | `MlKem768Ciphertext` |

libcrux ships F\* + hax-verified primitives; kyberlib ships a
`verified` feature ([#171](https://github.com/sebastienrousseau/kyberlib/issues/171))
that delegates to libcrux for downstream consumers who want
formal-verification provenance.

### From `oqs` / `oqs-rs`

```diff
-[dependencies]
-oqs = "0.10"
+[dependencies]
+kyberlib = "0.0.7"
```

```diff
-use oqs::kem::{Kem, Algorithm};
-let kem = Kem::new(Algorithm::MlKem768)?;
-let (pk, sk) = kem.keypair()?;
-let (ct, ss_a) = kem.encapsulate(&pk)?;
-let ss_b = kem.decapsulate(&sk, &ct)?;
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);
```

`liboqs` itself states "not for production"; kyberlib aims at
the production gap.

---

## Why this approach?

kyberlib targets the niche `RustCrypto/ml-kem` and `libcrux-ml-kem`
occupy — pure-Rust FIPS 203 ML-KEM — and adds the enterprise
delivery layer the competitors don't ship out of the box.

**Spec conformance, not just "it parses".** kyberlib is validated
against the **NIST ACVP corpus** (`usnistgov/ACVP-Server`) on
every commit: **60 / 60 ML-KEM-768 vectors pass byte-for-byte**.
The harness is checked in at
[`crates/kyberlib/tests/test_acvp.rs`](crates/kyberlib/tests/test_acvp.rs);
the vectors are in
[`crates/kyberlib/tests/acvp/`](crates/kyberlib/tests/acvp/). Run
with `make acvp` locally.

**`#![forbid(unsafe_code)]` on the safe core.** Default-feature
builds (no `avx2`, no `nasm`) compile with `unsafe` actively
forbidden by the compiler. The cfg-gated `forbid` lives at
[`crates/kyberlib/src/lib.rs:159`](crates/kyberlib/src/lib.rs).
SIMD intrinsics opt back in only when a backend feature is
explicitly enabled.

**KyberSlash-clean.** The TCHES 2025 class of timing
side-channels (secret-dependent `/`/`%` against `KYBER_Q`) is
audited and enforced going forward by `scripts/kyberslash-guard.sh`
in CI ([ADR 0003](doc/adr/0003-kyberslash-audit.md)). Reference
backend uses the upstream Barrett multiply-and-shift; AVX2 backend
uses SIMD multiply-high intrinsics — no `udiv`/`sdiv` on secret
inputs anywhere in the source tree.

**Secrets that defend themselves.** `MlKem768DecapKey` is
`!Copy`, `ZeroizeOnDrop`, and its `Debug` impl is redacted by
construction. `SharedSecret` is `ZeroizeOnDrop`. In plain English:
**the compiler enforces that secret keys cannot be accidentally
duplicated by an `=` assignment** (no implicit memcpy), **the
memory holding them is overwritten the moment the key goes out
of scope** (no leftover plaintext on the stack or heap), and
**no `println!("{:?}", key)` or panic backtrace can ever leak
the bytes** (the formatter prints `[REDACTED N bytes]`). The
legacy `Keypair` blob is retained for backward compatibility
but soft-deprecated in favour of the typed split (see
[Two APIs, one KEM](#two-apis-one-kem)).

**Signed releases.** Every tagged release ships with:

- a **SLSA L3 build provenance** attestation
  (`actions/attest-build-provenance`, recorded in the public
  Rekor transparency log);
- a **keyless cosign signature** over the `.crate` file
  (Fulcio + Rekor, no private key);
- a **CycloneDX 1.6 CBOM** carrying machine-readable
  `cryptoProperties` (parameter set, OID, security level, ACVP
  conformance).

Verification recipes in [Release artefacts](#release-artefacts).

**Backend flexibility, not lock-in.** The same public API
(`KemCore` trait) routes to one of three planned backends:

| Backend | Status | Feature |
|---|---|---|
| Pure Rust (default) | shipped | — |
| `aws-lc-rs` (FIPS 140-3) | planned | `fips` ([#170](https://github.com/sebastienrousseau/kyberlib/issues/170)) |
| `libcrux-ml-kem` (formally verified) | planned | `verified` ([#171](https://github.com/sebastienrousseau/kyberlib/issues/171)) |

Downstream consumers flip a feature flag; the call sites don't change.

---

## Capabilities in 0.0.7

| Capability | Status |
|---|---|
| FIPS 203 ML-KEM-768 keygen / encap / decap | ✓ ACVP 60/60 |
| FIPS 203 ML-KEM-512 / ML-KEM-1024 | typed wrappers ✓ · `KemCore` impl pending [#130c](https://github.com/sebastienrousseau/kyberlib/issues/130) |
| Implicit rejection (`J(z‖c)` per §6.3) | ✓ |
| KyberSlash audit + CI regression guard | ✓ [ADR 0003](doc/adr/0003-kyberslash-audit.md) |
| Typed `EncapsulationKey` / `DecapsulationKey` split | ✓ |
| `KemCore` trait (sealed, generic) | ✓ |
| `Zeroize` / `ZeroizeOnDrop` on secrets | ✓ unconditional |
| `no_std` + `alloc` | ✓ |
| WASM bindings | ✓ via [`kyberlib-wasm`](crates/kyberlib-wasm/) |
| X25519MLKEM768 hybrid | ✓ via [`kyberlib-hybrid`](crates/kyberlib-hybrid/) |
| AVX2 SIMD acceleration | ✓ `--features avx2` (x86_64 only) |
| NEON / AArch64 acceleration | planned [#172](https://github.com/sebastienrousseau/kyberlib/issues/172) |
| PKCS#8 / SPKI / PEM encoding | skeleton via [`kyberlib-pkcs8`](crates/kyberlib-pkcs8/) — full impl [#168](https://github.com/sebastienrousseau/kyberlib/issues/168) |
| FIPS 140-3 delegation (`aws-lc-rs`) | planned [#170](https://github.com/sebastienrousseau/kyberlib/issues/170) |
| Verified delegation (`libcrux-ml-kem`) | planned [#171](https://github.com/sebastienrousseau/kyberlib/issues/171) |
| SLSA L3 + cosign signed releases | ✓ release pipeline dry-run verified |
| CycloneDX 1.6 CBOM | ✓ generated per release |

---

## Two APIs, one KEM

kyberlib exposes two API surfaces over the same FIPS 203
primitives. New code should prefer the **typed `KemCore`** surface
(left column below). The **legacy free functions** (right column)
are retained for migration from v0.0.6 and from competitors with
similar surfaces (`pqcrypto-kyber`, older `ml-kem`).

| Action | Typed `KemCore` (preferred) | Legacy free functions |
|---|---|---|
| Generate keypair | `MlKem768::generate(&mut rng)?` | `kyberlib::keypair(&mut rng)?` |
| Encapsulate | `ek.encapsulate(&mut rng)?` | `kyberlib::encapsulate(&ek_bytes, &mut rng)?` |
| Decapsulate | `dk.decapsulate(&ct)` *(no `Result`)* | `kyberlib::decapsulate(&ct_bytes, &dk_bytes)?` |
| Secret type | `MlKem768DecapKey` (`!Copy`, redacted `Debug`) | `Keypair { public, secret }` (legacy blob) |

The typed surface enforces secret hygiene at the type level. The
legacy surface accepts and returns raw byte arrays — useful for
serialisation and migration from prior code, but the caller
becomes responsible for `!Copy` / `ZeroizeOnDrop` semantics on
the slice they handle.

---

## Ecosystem comparison

Short matrix. The full 30-row table (FIPS 203 conformance, ACVP,
formal verification, audit status, MSRV, no_std, WASM, SIMD,
constant-time validation, hybrid KEMs, PKCS#8, HPKE,
SBOM / CBOM / SLSA / sigstore / vet, FIPS 140-3 path,
download volume) is at [`doc/COMPARISON.md`](doc/COMPARISON.md).

| Capability | **kyberlib 0.0.7** | RustCrypto/ml-kem | libcrux-ml-kem | pqcrypto-kyber | oqs-rs | aws-lc-rs |
|---|---|---|---|---|---|---|
| Spec | FIPS 203 | FIPS 203 | FIPS 203 | Kyber R3 | Both | FIPS 203 |
| ACVP-validated | 60/60 ML-KEM-768 | yes | yes | n/a | yes | yes (CMVP) |
| Pure Rust | ✓ | ✓ | ✓ | C FFI | C FFI | C FFI |
| `#![forbid(unsafe_code)]` core | ✓ (cfg-gated) | ✓ | ✓ | n/a | n/a | n/a |
| Formal verification | — | — | ✓ (F\* + hax) | — | — | partial (SAW) |
| Third-party audit | gating v1.0 ([#177](https://github.com/sebastienrousseau/kyberlib/issues/177)) | — | (bugs in eprint 2026/192) | — | — | FIPS 140-3 |
| Hybrid X25519MLKEM768 | ✓ | external | ✓ | — | ✓ | partial |
| KyberSlash audit + guard | ✓ [ADR 0003](doc/adr/0003-kyberslash-audit.md) | post-CVE-2026-22705 | hax `secret_independence` | — | — | NIST-vetted |
| SLSA L3 + cosign release | ✓ | — | partial | — | — | — |
| CycloneDX 1.6 CBOM | ✓ | — | — | — | — | — |
| FIPS 140-3 path | planned via `fips` feature | — | — | — | — | ✓ |

---

## Benchmarks

> **Placeholder.** Headline numbers from `cargo bench --workspace`
> on an Apple M-series and on Linux x86_64 + AVX2. Final numbers
> land with [#176](https://github.com/sebastienrousseau/kyberlib/issues/176)
> and `doc/BENCHMARKS.md`. Comparison arms include
> `RustCrypto/ml-kem`, `libcrux-ml-kem`, `aws-lc-rs`,
> `pqcrypto-kyber`.

| Operation (ML-KEM-768) | kyberlib (reference) | kyberlib (`--features avx2`) | RustCrypto/ml-kem | libcrux-ml-kem | aws-lc-rs |
|---|---|---|---|---|---|
| `keygen` | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs |
| `encapsulate` | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs |
| `decapsulate` | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs |
| Combined (RT) | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs | _<TBD>_ μs |

| Hybrid (`X25519MlKem768`) | client share | server share | combined SS |
|---|---|---|---|
| Throughput | _<TBD>_ ops/s | _<TBD>_ ops/s | _<TBD>_ ops/s |

Bench harness: `criterion 0.5` + `codspeed` (continuous tracking
proposed under [#176](https://github.com/sebastienrousseau/kyberlib/issues/176)).

---

## Features

(See [the Cargo features table above](#cargo-features) for the
full list of `[features]` entries and what each pulls in.)

### Algorithm conformance

- FIPS 203 ML-KEM-768 — keygen / encapsulate / decapsulate
  byte-validated against NIST ACVP.
- Implicit rejection per FIPS 203 §6.3 — `J(z ‖ c) = SHAKE256(z‖c, 32)`
  on validation failure. `decapsulate` never panics, never
  branches on validity.
- Sealed `KemCore` trait — only kyberlib may implement.

### Memory hygiene

- `MlKem768DecapKey` is `!Copy + ZeroizeOnDrop`.
- `SharedSecret` is `ZeroizeOnDrop`. `Debug` redacted.
- Public types (`MlKem768EncapKey`, `MlKem768Ciphertext`) are
  `Copy + Clone` — non-secret data.

### Side-channel resilience

- Reference backend uses Barrett-style multiply-and-shift for
  every `/` and `%` against `KYBER_Q`. No `udiv`/`sdiv` on
  secret-derived integers anywhere — KyberSlash-clean
  ([ADR 0003](doc/adr/0003-kyberslash-audit.md)).
- AVX2 backend uses `_mm256_mulhi_epi16` /
  `_mm256_mulhrs_epi16` throughout — SIMD has no integer divide,
  so Barrett is structural.
- CI regression guard: `scripts/kyberslash-guard.sh` fails the
  build if any non-annotated `/[\s]*KYBER_Q` or `%[\s]*KYBER_Q`
  appears in source.

### Supply-chain

- `cargo deny` policy + CI gate.
- `cargo vet` imports from Mozilla, Google, Bytecode Alliance,
  Embark, Fermyon, ISRG, Zcash.
- Every GitHub Action pinned to a commit SHA, not `@vN`.
- `Cargo.lock` committed.
- No git-source dependencies in the production graph.

---

## Library usage

### Keygen → encapsulate → decapsulate (typed API)

```rust
use kyberlib::{KemCore, MlKem768};

let mut rng = rand::thread_rng();

let (dk, ek) = MlKem768::generate(&mut rng)?;            // sender holds ek; receiver holds dk
let ek_bytes = ek.as_bytes();                             // 1184 bytes — wire-serialise
let (ct, ss_sender) = ek.encapsulate(&mut rng)?;          // encapsulate against ek
let ss_receiver = dk.decapsulate(&ct);                    // decapsulate to recover ss

assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
```

### Hybrid (X25519MLKEM768) — TLS-draft-04 wire format

```rust
use kyberlib_hybrid::{X25519MlKem768Client, X25519MlKem768Server};
use rand::thread_rng;

let mut rng = thread_rng();

// Client side.
let (client_state, client_share) =
    X25519MlKem768Client::generate(&mut rng)?;             // 1216 bytes

// Server side.
let (server_share, ss_server) =
    X25519MlKem768Server::encapsulate(&mut rng, &client_share)?;  // 1120 bytes, 64-byte ss

// Client recovers the shared secret.
let ss_client = client_state.decapsulate(&server_share)?;
assert_eq!(ss_client, ss_server);
```

### Constant-time decapsulation (panics never)

```rust
// `decapsulate` never returns Result on the happy path — implicit
// rejection per FIPS 203 §6.3 returns a pseudorandom secret on
// invalid ciphertexts. No branching on validity.
let ss = dk.decapsulate(&ct_possibly_tampered);
// `ss` is either the real secret or a pseudorandom 32-byte value;
// distinguishing them requires the matching `dk`.
```

### Length-validated wire-format decoding

```rust
use kyberlib::MlKem768EncapKey;

// From a wire frame:
let ek = MlKem768EncapKey::try_from_slice(&wire_bytes)?;
// Returns Err(KyberLibError::InvalidLength) if not exactly 1184 bytes.
```

---

## Examples

| File | What it shows |
|---|---|
| [`examples/kem.rs`](crates/kyberlib/examples/kem.rs) | Minimal `keypair → encapsulate → decapsulate` round trip |
| [`examples/uake.rs`](crates/kyberlib/examples/uake.rs) | Unilaterally-authenticated key exchange (hazmat) |
| [`examples/ake.rs`](crates/kyberlib/examples/ake.rs) | Mutually-authenticated key exchange (hazmat) |

Run any one with `cargo run --example <name>` from the repo root.

---

## When not to use kyberlib

- **You need FIPS 140-3 certification today.** The `fips` feature
  delegating to `aws-lc-rs` is planned ([#170](https://github.com/sebastienrousseau/kyberlib/issues/170))
  but not yet shipped. For immediate CMVP compliance, depend on
  `aws-lc-rs` directly until the feature lands.
- **You need ML-KEM-512 or ML-KEM-1024 today.** The typed
  wrappers exist; the `KemCore` implementation is pending
  [#130c](https://github.com/sebastienrousseau/kyberlib/issues/130).
- **You're shipping production crypto and need an audit
  signature.** Third-party audit is gating v1.0
  ([#177](https://github.com/sebastienrousseau/kyberlib/issues/177)).
  Until that lands, treat v0.0.x as production-leaning but
  pre-audit; the audit RFP is ready at
  [`doc/audits/RFP-v1.0.md`](doc/audits/RFP-v1.0.md).
- **You need the ECDHE hybrid variants** (P-256 / P-384). Markers
  exist; implementation tracked under
  [#167b](https://github.com/sebastienrousseau/kyberlib/issues/167).
- **You're targeting `wasm32-unknown-unknown` from the core
  crate.** Use `kyberlib-wasm` instead — it carries the
  `wasm-bindgen` JS shim.
- **You want a runtime CLI.** kyberlib is library-only. A
  `kyberlib-cli` companion crate is not on the v1.0 roadmap.

---

## Development

```bash
make ci             # fmt-check + clippy + doc (strict) + test + deny + machete + kyberslash-guard
make acvp           # 60/60 NIST ACVP ML-KEM-768 vectors
make test-no-std    # safe core builds with --no-default-features
make miri           # focused Miri pass (nightly)
make fuzz-smoke     # 10-second cargo-fuzz against fuzz_decap
make dudect         # statistical CT analysis (scaffolded — phase 4.3)
make kyberslash-guard  # static `/ KYBER_Q` regression check
make sbom           # CycloneDX 1.5 SBOM (cargo-cyclonedx)
make cbom           # CycloneDX 1.6 CBOM with kyberlib's cryptoProperties
make vendor         # cargo vendor (air-gap simulation)
```

Full target list: `make help`.

### Workspace layout

```
crates/
  kyberlib/           safe core   ←  this README + most of the development effort
  kyberlib-asm/       SIMD/ASM     (skeleton — relocation of `src/avx2/` per #143)
  kyberlib-hybrid/    TLS hybrids  (X25519MlKem768 wired; ECDHE pending)
  kyberlib-pkcs8/     PKCS#8/SPKI  (skeleton — issue #168)
  kyberlib-wasm/      WASM shim
fuzz/                 cargo-fuzz harness (excluded from workspace)
scripts/              acvp-refresh, miri, dudect, cbom, kyberslash-guard
supply-chain/         cargo-vet config + audited imports
doc/                  ADRs, comparison, audit packet, patches
```

### Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) — Conventional Commits,
signed-commit requirement on `main`, ADR process for
API/architecture changes, crypto-specific conventions (Barrett
multiplication, no data-dependent branches on secrets, `unsafe`
quarantined to `kyberlib-asm`).

---

## Security

Full policy: [`SECURITY.md`](SECURITY.md).

**Disclosure.** Email **contact@kyberlib.com**. Do not file
public issues for security bugs. SLA: 48 h ack, 7 d triage,
30 d fix target for critical issues.

**In-scope threats.** Decapsulation oracles · timing
side-channels on `decapsulate` (secret-dependent) · memory
leaks of secret material · malformed-input panics · algorithm
confusion.

**Out-of-scope.** Physical-access attacks (cold-boot, JTAG,
fault injection) · compromise of the host kernel / hypervisor /
RNG source · caller's allocator side-channels · OS RNG source
attacks.

**Constant-time guarantees (per function).**

| Function | Reference impl | AVX2 impl |
|---|---|---|
| `decapsulate` (in secret key) | ✓ CT | ✓ CT (asm + intrinsics) |
| `encapsulate` (in public key) | ✓ CT | ✓ CT |
| `verify`, `cmov` | ✓ CT (audited bitwise) | ✓ CT |
| `poly_compress`, `poly_tomsg` | ✓ CT (KyberSlash audit clean — [ADR 0003](doc/adr/0003-kyberslash-audit.md)) | ✓ CT (SIMD multiply-high) |
| Key serialisation | ✓ CT in secret bytes | ✓ CT |

**Audit status.** Third-party audit packet ready at
[`doc/audits/`](doc/audits/) — RFP, materials package, readiness
checklist. Tracking [#177](https://github.com/sebastienrousseau/kyberlib/issues/177);
v1.0 will not tag until the audit signs off.

**Supply chain.** `cargo deny`, `cargo audit`, `cargo vet`
(imports from Mozilla / Google / Bytecode Alliance / Embark /
Fermyon / ISRG / Zcash), reproducible `cargo vendor --offline`
build verified in CI, every Action SHA-pinned, `Cargo.lock`
committed, signed commits enforced on `main`.

**FIPS / regulatory path.** Pure-Rust crates can't themselves be
FIPS 140-3 validated. The planned `fips` feature
([#170](https://github.com/sebastienrousseau/kyberlib/issues/170))
delegates to `aws-lc-rs` (the first cryptographic library to
include ML-KEM in a FIPS 140-3 validation, 2025) so the same
API serves both pure-Rust and CMVP-listed deployments.

---

## Release artefacts

Every tagged release ships:

| Artifact | Verification |
|---|---|
| `kyberlib-<version>.crate` | `cargo install kyberlib` |
| `kyberlib-<version>.crate.cosign-bundle.json` | `cosign verify-blob --bundle ... <crate>` |
| SLSA L3 attestation | `gh attestation verify --owner sebastienrousseau <crate>` |
| `cbom.cdx.json` | CycloneDX 1.6 — machine-readable algorithm metadata |
| `SHA256SUMS`, `SHA512SUMS` | `shasum -a 256 -c SHA256SUMS` |

Full verification recipe:

```bash
gh release download v0.0.7 --pattern '*.crate' \
                            --pattern '*.cosign-bundle.json' \
                            --pattern 'SHA256SUMS'

# Provenance (Rekor transparency log)
gh attestation verify --owner sebastienrousseau kyberlib-0.0.7.crate

# Keyless cosign signature (Fulcio + Rekor)
cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/sebastienrousseau/kyberlib/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle kyberlib-0.0.7.crate.cosign-bundle.json \
    kyberlib-0.0.7.crate

# Checksums
shasum -a 256 -c SHA256SUMS
```

The release pipeline (`.github/workflows/release.yml`) is
dry-run verified — see [`doc/audits/READINESS.md`](doc/audits/READINESS.md).

---

## Documentation

| Document | Purpose |
|---|---|
| [`CHANGELOG.md`](CHANGELOG.md) | Keep-a-Changelog 1.1.0 — every release entry |
| [`SECURITY.md`](SECURITY.md) | Threat model, CT guarantees, disclosure SLA |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Conventional Commits, signed commits, ADR process |
| [`doc/COMPARISON.md`](doc/COMPARISON.md) | Full comparison vs. ml-kem / libcrux / oqs / aws-lc-rs |
| [`doc/BENCHMARKS.md`](doc/BENCHMARKS.md) | Detailed benchmark numbers *(landing with [#176](https://github.com/sebastienrousseau/kyberlib/issues/176))* |
| [`doc/adr/0001-fips203-migration.md`](doc/adr/0001-fips203-migration.md) | Kyber R3 → FIPS 203 rationale + byte-deltas |
| [`doc/adr/0002-asm-quarantine.md`](doc/adr/0002-asm-quarantine.md) | Splitting `unsafe` into `kyberlib-asm` |
| [`doc/adr/0003-kyberslash-audit.md`](doc/adr/0003-kyberslash-audit.md) | KyberSlash audit + regression-guard scheme |
| [`doc/adr/0004-multi-param-strategy.md`](doc/adr/0004-multi-param-strategy.md) | The `hybrid-array` plan for ML-KEM-512 / ML-KEM-1024 |
| [`doc/audits/`](doc/audits/) | RFP, materials package, readiness checklist for the v1.0 audit |
| [`doc/patches/`](doc/patches/) | Cryptographic patch review packets (e.g. Phase 2(b) FIPS 203) |

Rendered API docs: <https://docs.rs/kyberlib>

---

## License

Dual-licensed under either of:

- **[Apache 2.0](LICENSE-APACHE)** (`Apache-2.0`)
- **[MIT](LICENSE-MIT)** (`MIT`)

at your option. SPDX identifier: `Apache-2.0 OR MIT`. By
submitting a contribution, you agree your work is licensed
under both.

---

THE ARCHITECT ᛫ Sebastien Rousseau ᛫ https://sebastienrousseau.com
THE ENGINE ᛞ EUXIS ᛫ Enterprise Unified Execution Intelligence System ᛫ https://euxis.co

<p align="right"><a href="#kyberlib">Back to top</a></p>
