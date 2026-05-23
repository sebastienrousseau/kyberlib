<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg" alt="kyberlib logo" width="128" />
</p>

<h1 align="center">kyberlib</h1>

<p align="center"><em>Last Updated: 2026-05-22</em></p>

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

- [Install](#install) — Cargo, source, `no_std`
- [Quick Start](#quick-start) — typed `KemCore` API in ten lines

**Library reference**

- [Migrating to FIPS 203 ML-KEM](#migrating-to-fips-203-ml-kem) — `diff`-style snippets from `pqcrypto-kyber`, `RustCrypto/ml-kem`, `libcrux-ml-kem`, `oqs-rs`, and the legacy `kyberlib` 0.0.6 surface
- [Why this approach?](#why-this-approach) — design rationale
- [Capabilities in 0.0.7](#capabilities-in-007) — release inventory
- [Two APIs, one KEM](#two-apis-one-kem) — legacy free functions vs. type-state `KemCore`
- [Features](#features) — Cargo-feature capability list
- [Library usage](#library-usage) — keygen, encapsulate, decapsulate
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use kyberlib](#when-not-to-use-kyberlib) — limitations
- [Development](#development) — make targets, fuzzing, Miri, dudect, ACVP
- [Security](#security) — threat model, CT guarantees, audit posture
- [Release artefacts](#release-artefacts) — SLSA L3 + cosign + CBOM verification
- [Documentation](#documentation) — all reference docs
- [The kyberlib ecosystem](#the-kyberlib-ecosystem) — satellite crates
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

### Build from source

```bash
git clone https://github.com/sebastienrousseau/kyberlib.git
cd kyberlib
make ci          # fmt + clippy + doc + test + deny + machete + kyberslash-guard
```

### `no_std` support

```toml
[dependencies]
kyberlib = { version = "0.0.7", default-features = false, features = ["kyber768"] }
```

Requires `alloc` (because of `Vec` buffers in the rejection sampler).
The safe core compiles for `wasm32-unknown-unknown`, embedded ARM
targets, and any other `alloc`-capable, no-`std` host. Enabling
`std` adds `std::error::Error` impls and the `getrandom`-backed
default RNG.

**Bring your own RNG.** Every keygen / encapsulate entry point
takes an `&mut R` where `R: rand_core::CryptoRng +
rand_core::RngCore`. On embedded targets you'd typically pass a
hardware-RNG wrapper:

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
on bare metal, plug a vetted TRNG. `kyberlib` never reaches for
`std::*` to find randomness — the caller is always in control.

### MSRV

The declared MSRV is **Rust 1.74**. A dedicated `msrv` CI job gates
this on every PR.

---

## Quick Start

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    // (1) Generate a key pair. `dk` is `!Copy` + ZeroizeOnDrop.
    let (dk, ek) = MlKem768::generate(&mut rng)?;

    // (2) Sender encapsulates a fresh shared secret against the receiver's public key.
    let (ct, ss_a) = ek.encapsulate(&mut rng)?;

    // (3) Receiver decapsulates with their secret key — gets the same shared secret.
    let ss_b = dk.decapsulate(&ct);

    // Both sides now hold the same 32-byte shared secret.
    assert_eq!(ss_a, ss_b);
    Ok(())
}
```

That's a complete ML-KEM-768 round-trip in ten lines. The same
shape works for ML-KEM-512 (`MlKem512`) and ML-KEM-1024
(`MlKem1024`) — all three parameter sets coexist in any single
build of `kyberlib`.

---

## Migrating to FIPS 203 ML-KEM

`kyberlib` v0.0.7 implements **FIPS 203 ML-KEM** (NIST, August
2024) — the standardised form of CRYSTALS-Kyber Round 3. v0.0.6
and earlier shipped the Round-3 surface. The byte-level deltas
(K-byte domain separator, dropped `m' = H(m)` pre-hash, dropped
final KDF + `J(z‖c)` rejection branch) are documented in
[ADR 0001](../../doc/adr/0001-fips203-migration.md). Five concrete
migration paths follow.

### From `kyberlib` 0.0.6 → 0.0.7

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
still works — it is soft-deprecated and delegates to the typed
API. Shared-secret bytes change vs. 0.0.6 because of the FIPS 203
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
-use pqcrypto_kyber::kyber768::*;
-let (pk, sk) = keypair();
-let (ss_a, ct) = encapsulate(&pk);
-let ss_b = decapsulate(&ct, &sk);
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);
```

`pqcrypto-kyber` wraps the C reference implementation; `kyberlib`
is pure Rust. Wire-format identical (both FIPS 203 final).

### From `RustCrypto/ml-kem`

```diff
-[dependencies]
-ml-kem = "0.2"
+[dependencies]
+kyberlib = "0.0.7"
```

```diff
-use ml_kem::{kem::{Decapsulate, Encapsulate}, MlKem768};
-let (dk, ek) = MlKem768::generate(&mut rng);
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
```

The `RustCrypto/ml-kem` surface inspires the v0.0.7 `KemCore`
shape. The difference: `kyberlib` returns `Result` from
`generate` / `encapsulate` for length-validated typed wrappers,
ships ACVP-conformant byte streams out of the box, and includes
the KyberSlash regression gate.

### From `libcrux-ml-kem`

| `libcrux-ml-kem` (verified Rust) | `kyberlib` (pure Rust) |
|---|---|
| `libcrux_ml_kem::mlkem768::generate_key_pair_unpacked(seed)` | `MlKem768::generate(&mut rng)` |

`libcrux-ml-kem` is the F\* + hax verified backend. `kyberlib`
plans to delegate to it under the `verified` feature flag
([ADR 0006](../../doc/adr/0006-fips-facade.md), tracked in
[#171](https://github.com/sebastienrousseau/kyberlib/issues/171))
— letting consumers pick "speed" (pure-Rust + AVX2) vs. "proof"
(libcrux-verified) at compile time without changing call sites.

### From `oqs-rs`

```diff
-use oqs::kem::{Algorithm, Kem};
-let kem = Kem::new(Algorithm::Kyber768)?;
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
```

`oqs-rs` wraps `liboqs` — a useful aggregator of many PQC
algorithms but with a heavy native dependency. `kyberlib` is the
focused single-algorithm pure-Rust pick.

---

## Why this approach?

`kyberlib` targets the niche `RustCrypto/ml-kem` and
`libcrux-ml-kem` occupy — pure-Rust FIPS 203 ML-KEM — and adds
the enterprise delivery layer the competitors don't ship out of
the box.

**Spec conformance, not just "it parses".** `kyberlib` is
validated against the **NIST ACVP corpus** (`usnistgov/ACVP-Server`)
on every commit: **60 / 60 ML-KEM-768 vectors pass byte-for-byte**.
The harness is checked in at
[`tests/test_acvp.rs`](tests/test_acvp.rs); the vectors live in
[`tests/acvp/`](tests/acvp/). Run with `make acvp` locally.

**`#![forbid(unsafe_code)]` on the safe core.** Default-feature
builds (no `avx2`, no `nasm`) compile with `unsafe` actively
forbidden by the compiler. The cfg-gated `forbid` lives at
[`src/lib.rs:159`](src/lib.rs). SIMD intrinsics opt back in only
when a backend feature is explicitly enabled.

**KyberSlash-clean.** The TCHES 2025 class of timing
side-channels (secret-dependent `/`/`%` against `KYBER_Q`) is
audited and enforced going forward by `scripts/kyberslash-guard.sh`
in CI ([ADR 0003](../../doc/adr/0003-kyberslash-audit.md)). The
reference backend uses the upstream Barrett multiply-and-shift;
the AVX2 backend uses SIMD multiply-high intrinsics — no
`udiv`/`sdiv` on secret inputs anywhere in the source tree.

**Secrets that defend themselves.** `MlKem768DecapKey` is
`!Copy`, `ZeroizeOnDrop`, and its `Debug` impl is redacted by
construction. `SharedSecret` is `ZeroizeOnDrop`. In plain English:
**the compiler enforces that secret keys cannot be accidentally
duplicated by an `=` assignment** (no implicit memcpy), **the
memory holding them is overwritten the moment the key goes out
of scope** (no leftover plaintext on the stack or heap), and
**no `println!("{:?}", key)` or panic backtrace can ever leak
the bytes** (the formatter prints `[REDACTED N bytes]`). The
legacy `Keypair` blob is retained for backward compatibility but
soft-deprecated in favour of the typed split (see
[Two APIs, one KEM](#two-apis-one-kem)).

**Signed releases.** Every tagged release of `kyberlib` ships with:

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
| All three parameter sets in one build | ✓ const-generic refactor [#130b](https://github.com/sebastienrousseau/kyberlib/issues/130) |
| Implicit rejection (`J(z‖c)` per §6.3) | ✓ |
| KyberSlash audit + CI regression guard | ✓ [ADR 0003](../../doc/adr/0003-kyberslash-audit.md) |
| Typed `EncapsulationKey` / `DecapsulationKey` split | ✓ |
| `KemCore` trait (sealed, generic) | ✓ |
| `Zeroize` / `ZeroizeOnDrop` on secrets | ✓ unconditional |
| `no_std` + `alloc` | ✓ |
| AVX2 SIMD acceleration | ✓ `--features avx2` (x86_64 only) |
| NEON / AArch64 acceleration | planned [#172](https://github.com/sebastienrousseau/kyberlib/issues/172) |
| FIPS 140-3 delegation (`aws-lc-rs`) | planned [#170](https://github.com/sebastienrousseau/kyberlib/issues/170) |
| Verified delegation (`libcrux-ml-kem`) | planned [#171](https://github.com/sebastienrousseau/kyberlib/issues/171) |
| SLSA L3 + cosign signed releases | ✓ release pipeline dry-run verified |
| CycloneDX 1.6 CBOM | ✓ generated per release |
| WebAssembly bindings | ✓ via [`kyberlib-wasm`](https://crates.io/crates/kyberlib-wasm) |
| TLS hybrid (X25519MLKEM768) | ✓ via [`kyberlib-hybrid`](https://crates.io/crates/kyberlib-hybrid) |
| PKCS#8 / SPKI / PEM encoding | skeleton via [`kyberlib-pkcs8`](https://crates.io/crates/kyberlib-pkcs8) |

---

## Two APIs, one KEM

`kyberlib` exposes two API surfaces over the same FIPS 203
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

## Features

All non-essential features are opt-in. Enable only what your
application needs.

| Feature | Default? | Pulls in | Adds | Documented in |
|---|---|---|---|---|
| `kyber768`         | ✓ | — | ML-KEM-768 parameter set (the default) | [Capabilities](#capabilities-in-007) |
| `std`              | ✓ | — | `std::error::Error` impl; `getrandom`-backed default RNG | [Install](#install) |
| `kyber512`         |   | — | ML-KEM-512 parameter set | `paramsets.rs` |
| `kyber1024`        |   | — | ML-KEM-1024 parameter set | `paramsets.rs` |
| `hazmat`           |   | — | IND-CPA primitives — bypasses the FO transform; use with care | [docs.rs `reference::indcpa`](https://docs.rs/kyberlib) |
| `90s`              |   | `sha2` | AES-CTR + SHA-2 instead of SHAKE (Kyber-R3 era; removed from FIPS 203) | CHANGELOG |
| `90s-fixslice`     |   | `aes`, `ctr` | Bitsliced AES for side-channel hardening of 90s mode | CHANGELOG |
| `avx2`             |   | `cc` | x86_64 SIMD acceleration of the polynomial arithmetic | [`kyberlib-asm`](https://crates.io/crates/kyberlib-asm) |
| `nasm`             |   | `nasm-rs`, `avx2` | NASM-assembled AVX2 (portable to non-GAS toolchains) | [`kyberlib-asm`](https://crates.io/crates/kyberlib-asm) |
| `wasm`             |   | — | **Legacy / Compat (no-op):** retained for v0.0.6 compatibility — real WASM bindings live in [`kyberlib-wasm`](https://crates.io/crates/kyberlib-wasm). Do not enable. | CHANGELOG |
| `zeroize`          |   | — | **Legacy / Compat (no-op):** retained for v0.0.6 compatibility — `ZeroizeOnDrop` is unconditional since v0.0.7. Do not enable. | CHANGELOG |
| `benchmarking`     |   | — | Re-exports internal `kem` module for the `benches/api.rs` harness. Not for production. | [`benches/api.rs`](benches/api.rs) |
| `fips`             |   | (stub) | Planned `aws-lc-rs` delegation for FIPS 140-3 customers — [#170](https://github.com/sebastienrousseau/kyberlib/issues/170) | [SECURITY](../../SECURITY.md) |
| `verified`         |   | (stub) | Planned `libcrux-ml-kem` delegation for formally-verified primitives — [#171](https://github.com/sebastienrousseau/kyberlib/issues/171) | [SECURITY](../../SECURITY.md) |

```toml
# Example: production server with x86_64 SIMD acceleration
[dependencies]
kyberlib = { version = "0.0.7", features = ["avx2"] }
```

---

## Library usage

Full round-trip with the typed `KemCore` API:

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng)?;    // sender holds ek; receiver holds dk

    // Wire: ek.as_bytes() over the network (1184 bytes for ML-KEM-768).

    let (ct, ss_a) = ek.encapsulate(&mut rng)?;       // sender derives ss_a + emits ct
    // Wire: ct.as_bytes() over the network (1088 bytes for ML-KEM-768).

    let ss_b = dk.decapsulate(&ct);                   // receiver recovers ss_b
    assert_eq!(ss_a, ss_b);                            // 32-byte shared secret
    Ok(())
}
```

The legacy free-function surface for migration from v0.0.6 or
competitor crates:

```rust
use kyberlib::{keypair, encapsulate, decapsulate};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng)?;
    let (ct, ss_a) = encapsulate(&keys.public, &mut rng)?;
    let ss_b = decapsulate(&ct, &keys.secret)?;
    assert_eq!(ss_a, ss_b);
    Ok(())
}
```

For the deeper architectural picture see
[`doc/architecture.md`](doc/architecture.md); for the FIPS 203
spec migration narrative see [ADR 0001](../../doc/adr/0001-fips203-migration.md).

---

## Examples

Runnable Rust examples live in [`examples/`](examples/):

| Example | What it shows |
|---|---|
| `examples/kem.rs` | Minimal keygen / encap / decap with the legacy free-function API |
| `examples/uake.rs` | Unilaterally-authenticated KEX (`Uake`) round-trip |
| `examples/ake.rs` | Mutually-authenticated KEX (`Ake`) round-trip |
| `examples/typed_kem.rs` | Same round-trip with the typed `KemCore` / `MlKem768` surface |
| `examples/deterministic_seed.rs` | Deterministic keygen from a 64-byte seed (KAT-friendly) |
| `examples/no_std_demo.rs` | `#![no_std]`-compatible round-trip with a caller-supplied RNG |

Each example is commented to explain *why* each step is needed,
not just *what* the code does. Run with:

```bash
cargo run --example kem
cargo run --example uake
cargo run --example ake
cargo run --example typed_kem
cargo run --example deterministic_seed
cargo run --example no_std_demo
```

Copy-pasteable recipe collection: [`doc/cookbook.md`](doc/cookbook.md)
(vanilla KEM, runtime parameter-set choice, deterministic keygen,
wire serialisation, no_std, mutually-authenticated KEX, AEAD
integration, TLS hybrid pointer).

---

## When not to use kyberlib

`kyberlib` is the right pick for pure-Rust FIPS 203 ML-KEM. It is
**not** the right pick for:

- **Browser / JavaScript consumers** — use
  [`kyberlib-wasm`](https://crates.io/crates/kyberlib-wasm)
  instead, which ships the same FIPS 203 primitives through a
  `wasm-bindgen` boundary at ~120 KiB compressed.
- **Hybrid (X25519MLKEM768) TLS key exchange** — use
  [`kyberlib-hybrid`](https://crates.io/crates/kyberlib-hybrid),
  which wires the
  [`draft-ietf-tls-ecdhe-mlkem-04`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
  client + server surfaces on top of `kyberlib` and
  `x25519-dalek`.
- **PKCS#8 / SPKI / PEM key encoding** — use
  [`kyberlib-pkcs8`](https://crates.io/crates/kyberlib-pkcs8)
  (skeleton in v0.0.7; full impl in
  [#168](https://github.com/sebastienrousseau/kyberlib/issues/168)).
- **CMVP-validated FIPS 140-3 cryptography** — the `fips` feature
  ([ADR 0006](../../doc/adr/0006-fips-facade.md), planned for
  v0.0.9) will delegate to `aws-lc-rs`'s in-process CMVP-validated
  ML-KEM. Until that lands, use `aws-lc-rs` directly.
- **Streaming encryption** — ML-KEM is a key encapsulation
  mechanism, not a cipher. Use the 32-byte shared secret as a key
  to a symmetric AEAD (`chacha20poly1305`, `aes-gcm`, `WebCrypto`
  AES-GCM in the browser). See `doc/cookbook.md` for the recipe.
- **Power-analysis-resistant hardware** — `kyberlib` is
  software-only. Hardware countermeasures (masking, randomised
  execution) are out of scope.

---

## Development

```sh
# Run the full local CI superset.
make ci

# Targeted gates.
make fmt-check               # cargo fmt --all -- --check
make clippy                  # cargo clippy ... -- -D warnings
make test                    # cargo test --workspace
make doc                     # cargo doc --no-deps --workspace
make deny                    # cargo deny check (advisories + licenses + bans)
make kyberslash-guard        # scripts/kyberslash-guard.sh (ADR 0003)

# Security tooling — via the xtask runner.
cargo xtask kyberslash       # KyberSlash regression guard
cargo xtask miri             # focused Miri (60 min)
cargo xtask miri full        # full Miri sweep (~90 min, incl. big-endian)
cargo xtask dudect quick     # dudect CT analysis (5k samples)
cargo xtask dudect full      # dudect CT analysis (200k samples)
cargo xtask cbom             # generate CycloneDX 1.6 CBOM
cargo xtask acvp-refresh     # refresh NIST ACVP vectors
cargo xtask all-gates        # everything green

# Benches (criterion + dudect-bencher).
make bench                   # full criterion run + HTML report
make bench-quick             # quick smoke (~2 min)
```

See [`doc/release-process.md`](doc/release-process.md) for the
release-cut checklist.

---

## Security

`kyberlib` carries a strong default-feature security posture:
constant-time primitives, audited Barrett reduction, FIPS 203 §6.3
implicit rejection, unconditional `ZeroizeOnDrop` on secrets, and
`#![forbid(unsafe_code)]` on the safe core.

**Constant-time guarantees**: see [`doc/safety.md`](doc/safety.md)
for the three-layer story (Barrett structural, `verify` + `cmov`
algorithmic, dudect empirical) and the workspace
[`SECURITY.md`](../../SECURITY.md) for the threat model, the
per-function CT-guarantees table, and the audit posture.

**Reporting vulnerabilities**: see
[`SECURITY.md`](../../SECURITY.md) at the workspace root for the
disclosure process.

---

## Release artefacts

Every `v*.*.*` tag triggers the release pipeline at
[`.github/workflows/release.yml`](../../.github/workflows/release.yml).
The pipeline emits, for `kyberlib`:

- a **SLSA L3 build provenance** attestation
  (`actions/attest-build-provenance`, recorded in the public
  Rekor transparency log);
- a **keyless cosign signature** over the `.crate` file
  (Fulcio + Rekor, no private key);
- a **CycloneDX 1.6 CBOM** with machine-readable
  `cryptoProperties` (parameter set, OID, security level,
  ACVP conformance);
- SHA-256 + SHA-512 of every artefact.

Verification recipes for downstream consumers:

```sh
# Verify SLSA L3 provenance:
gh attestation verify --owner sebastienrousseau kyberlib-0.0.7.crate

# Verify cosign signature:
cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/sebastienrousseau/kyberlib/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle kyberlib-0.0.7.crate.cosign-bundle.json \
    kyberlib-0.0.7.crate
```

---

## Documentation

| Document | What it covers |
|---|---|
| [`doc/architecture.md`](doc/architecture.md) | Module map, two APIs, const-generic pipeline, backends, safety boundaries |
| [`doc/safety.md`](doc/safety.md) | Unsafe-code policy, CT guarantees in 3 layers, panic-freedom, secret handling |
| [`doc/cookbook.md`](doc/cookbook.md) | Copy-pasteable recipes (round-trip, no_std, hybrid, AEAD integration) |
| [`doc/migration-from-0.0.6.md`](doc/migration-from-0.0.6.md) | Explicit before/after for the v0.0.6 → v0.0.7 breaking changes |
| [`doc/release-process.md`](doc/release-process.md) | Maintainer checklist for cutting a release |
| [`../../README.md`](../../README.md) | Workspace root README — ecosystem overview |
| [`../../doc/COMPARISON.md`](../../doc/COMPARISON.md) | kyberlib vs. competing Rust ML-KEM crates |
| [`../../doc/BENCHMARKS.md`](../../doc/BENCHMARKS.md) | criterion + dudect numbers + reproduction recipe |
| [`../../SECURITY.md`](../../SECURITY.md) | Threat model, CT guarantees, audit posture, FIPS path |
| [`../../doc/adr/`](../../doc/adr/) | Architecture decision records (FIPS 203, asm quarantine, KyberSlash, multi-param, BYOE deterministic API, FIPS facade) |

---

## The kyberlib ecosystem

`kyberlib` is the core of a small workspace of focused crates:

| Crate | What it is | Status (v0.0.7) |
|---|---|---|
| **[`kyberlib`](https://crates.io/crates/kyberlib)** (this) | Core library — FIPS 203 ML-KEM | Published; ACVP 60/60 |
| [`kyberlib-asm`](https://crates.io/crates/kyberlib-asm) | AVX2 / NEON / SIMD acceleration backend | Skeleton — [#143](https://github.com/sebastienrousseau/kyberlib/issues/143) |
| [`kyberlib-hybrid`](https://crates.io/crates/kyberlib-hybrid) | TLS 1.3 hybrid KEMs — X25519MLKEM768 + ECDHE variants | `X25519MlKem768` wired |
| [`kyberlib-pkcs8`](https://crates.io/crates/kyberlib-pkcs8) | PKCS#8 / SPKI / PEM encoding with LAMPS-registered OIDs | Skeleton — [#168](https://github.com/sebastienrousseau/kyberlib/issues/168) |
| [`kyberlib-wasm`](https://crates.io/crates/kyberlib-wasm) | `wasm-bindgen` wrapper for browser / Node / Workers / Deno | Published alongside `kyberlib` |

See the workspace [`README.md`](../../README.md) for the full
ecosystem context and the [`doc/adr/`](../../doc/adr/) directory
for the architecture decision records.

---

## License

`kyberlib` is dual-licensed under either of:

- [Apache License, Version 2.0](../../LICENSE-APACHE)
  ([http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- [MIT License](../../LICENSE-MIT)
  ([http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work,
as defined in the Apache-2.0 license, shall be dual-licensed as
above, without any additional terms or conditions.

REUSE-compliant SPDX headers are present on every source file in
the workspace; see the per-crate `LICENSES/` directory and the
workspace [`REUSE.toml`](../../REUSE.toml) for the machine-
readable licensing metadata.
