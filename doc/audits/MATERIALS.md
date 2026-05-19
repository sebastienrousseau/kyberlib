# kyberlib — Audit materials package

> The complete set of links, commit SHAs, and pointers the maintainer
> hands to a vendor on contract signing. Pair with `RFP-v1.0.md`.

## 1. The repository

* Clone: `git clone https://github.com/sebastienrousseau/kyberlib.git`
* Audit branch: `feat/v0.0.7`
* HEAD at audit kickoff: (filled in at handover — see the maintainer's
  pin-commit reference in the contract exhibit)

## 2. Documents to read first (in order)

| # | File | Purpose |
|---|------|---------|
| 1 | `README.md` | What kyberlib does and how to install it |
| 2 | `SECURITY.md` | Threat model, CT guarantees, FIPS path, disclosure SLA |
| 3 | `CHANGELOG.md` (the `[0.0.7]` block) | What changed in this release |
| 4 | `doc/COMPARISON.md` | How kyberlib stacks against `ml-kem`, `libcrux-ml-kem`, `oqs`, `aws-lc-rs` |
| 5 | `doc/adr/0001-fips203-migration.md` | Why and how kyberlib migrated from Kyber R3 to FIPS 203 |
| 6 | `doc/adr/0002-asm-quarantine.md` | The `kyberlib-asm` separation strategy |
| 7 | `doc/adr/0003-kyberslash-audit.md` | The KyberSlash audit + regression-guard scheme |
| 8 | `doc/patches/phase-2b-evidence.md` | Per-patch ACVP evidence for the FIPS 203 migration |

## 3. Code to read (suggested route)

### Primary surface

1. `crates/kyberlib/src/lib.rs` — crate root + re-exports.
2. `crates/kyberlib/src/ml_kem.rs` — the typed FIPS 203 API
   (`KemCore` trait, `MlKem768` marker, `EncapsulationKey`,
   `DecapsulationKey`, `Ciphertext`, `SharedSecret`).
3. `crates/kyberlib/src/kem.rs` — the IND-CCA wrapper (encrypt /
   decrypt with implicit rejection).
4. `crates/kyberlib/src/reference/indcpa.rs` — IND-CPA layer.
5. `crates/kyberlib/src/reference/poly.rs` — polynomial arithmetic
   and the KyberSlash-patched compression.
6. `crates/kyberlib/src/reference/verify.rs` — constant-time
   `verify` and `cmov`.
7. `crates/kyberlib/src/symmetric.rs` — `G` / `H` / `J` / `KDF`
   plumbing on top of SHA3 / SHAKE.
8. `crates/kyberlib/src/reference/reduce.rs` — Barrett + Montgomery
   reduction.

### Hybrid surface

9. `crates/kyberlib-hybrid/src/lib.rs` — X25519MlKem768
   implementation per `draft-ietf-tls-ecdhe-mlkem-04`.

### AVX2 backend (separate review pass)

10. `crates/kyberlib/src/avx2/` — SIMD primitives. Audit attention
    on `unsafe` block coverage and the GAS/NASM assembly.

### Tests

11. `crates/kyberlib/tests/test_acvp.rs` — NIST ACVP harness.
12. `crates/kyberlib/tests/test_*.rs` — round-trip and unit tests.
13. `fuzz/fuzz_targets/*.rs` — libFuzzer corpus.

## 4. Specific commits to review

The Phase 2(b) FIPS 203 migration was deliberately landed as three
atomic commits so each is bisectable. Audit each independently for
crypto correctness and observable behaviour:

| Commit | Subject | What it changes |
|--------|---------|------------------|
| `417595a` | FIPS 203 §5.1 — append k_byte to G(d) for keygen | `crates/kyberlib/src/reference/indcpa.rs::indcpa_keypair` |
| `27e4b6b` | FIPS 203 §6.2 — drop m'=H(m) pre-hash in encaps | `crates/kyberlib/src/kem.rs::encrypt_message` |
| `b0f3bfb` | FIPS 203 §6.2/§6.3 — drop final KDF; J(z‖c) on rejection | `crates/kyberlib/src/kem.rs::{encrypt_message, decrypt_message}` |
| `18ba0d9` | KyberSlash audit (ADR 0003) — clean; add regression gate | source annotations + `scripts/kyberslash-guard.sh` |
| `a6065cc` | Phase 3 — sealed KemCore trait + typed ML-KEM-768 surface | new public API |
| `5eb7bd5` | X25519MlKem768 — Phase 5.1 implementation | `crates/kyberlib-hybrid/src/lib.rs` |

## 5. Test corpus

### NIST ACVP ML-KEM vectors

Location: `crates/kyberlib/tests/acvp/`

* `keyGen-prompt.json` / `keyGen-expected.json` — 75 cases across
  ML-KEM-{512, 768, 1024}.
* `encapDecap-prompt.json` / `encapDecap-expected.json` — 165 cases
  including the keyCheck variants.
* `SHA256SUMS` — checksums to verify against the canonical
  `usnistgov/ACVP-Server` master.

Run with:

```sh
make acvp                # or
RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' \
  cargo test -p kyberlib --test test_acvp -- --nocapture
```

Expected: **60 / 60 ML-KEM-768 cases pass**. ML-KEM-512 and
ML-KEM-1024 vectors load but their test cases are skipped
(parameter sets not yet wired — tracked under #130b).

### Legacy Kyber Round 3 KAT (archival)

Location: `crates/kyberlib/tests/KAT/`. Intentionally invalid after
the FIPS 203 migration; included for historical regression only.
Does not run by default.

## 6. CI artefacts

* `.github/workflows/ci.yml` — the per-PR gates: clippy, fmt, test,
  cargo-deny, cargo-machete, semver-checks, miri, fuzz-smoke,
  msrv (1.74), no_std, vendor-build, kyberslash-guard, rustdoc strict.
* `.github/workflows/release.yml` — tag-triggered with SLSA L3
  attestation + cosign keyless signing + CycloneDX SBOM/CBOM.

## 7. Threat model + invariants (cheatsheet)

| Invariant | Where enforced |
|-----------|----------------|
| `decapsulate` never panics, never branches on validity | `crates/kyberlib/src/kem.rs::decrypt_message`; FIPS 203 §6.3 implicit rejection |
| Public API on the safe core: zero `unsafe` | `#![cfg_attr(not(any(feature = "avx2", feature = "nasm")), forbid(unsafe_code))]` at lib.rs root |
| Secret keys are `!Copy + ZeroizeOnDrop` | `MlKem768DecapKey` in `crates/kyberlib/src/ml_kem.rs`; legacy `Keypair` likewise |
| No secret-dependent `/` or `%` against `KYBER_Q` | `scripts/kyberslash-guard.sh` CI gate + 5 audited `// kyberslash-guard: safe` annotations |
| Length validation surfaces `Err(InvalidInput / InvalidLength)`, never panics | `try_from_slice` constructors on the typed wrappers; `fuzz/fuzz_targets/fuzz_decap.rs` exercises this |
| Constant-time `verify` and `cmov` | `crates/kyberlib/src/reference/verify.rs` |

## 8. Build matrix to exercise

```sh
# Default features
cargo build --workspace

# Strict no_std (safe core only)
cargo build -p kyberlib --lib --no-default-features --features kyber768

# All features
cargo build --workspace --all-features

# MSRV 1.74
cargo +1.74.0 check --workspace --all-features

# Vendor / air-gap simulation
cargo vendor --versioned-dirs vendor
cargo build --offline --locked --all-features
```

## 9. Known not-yet-fixed items the audit should expect

The audit is going to find these because we already know about them.
Flag if they're materially different from how we've documented them:

* **AVX2 backend's `indcpa_keypair` still needs the K-byte patch.**
  The reference impl carries the fix; the AVX2 mirror is tracked
  under #143 because the AVX2 build doesn't compile on the
  maintainer's aarch64 macOS workstation. The ACVP harness only
  exercises the reference path.
* **ML-KEM-512 and ML-KEM-1024 are not yet built.** The marker types
  are declared but unimplemented (#130b).
* **`Uake` and `Ake`** in `crates/kyberlib/src/kex.rs` are
  experimental key-exchange helpers, not part of the FIPS 203 KEM
  surface. They should not be in production use.
* **The legacy `keypair()` / `Keypair`** is soft-deprecated. Audits
  attention should be on the typed `MlKem768::generate()` path.
* **`dudect` harness is scaffolded, not wired.** The gating
  preconditions (FIPS 203 migration + KyberSlash audit) are now
  satisfied but the actual `dudect-bencher` integration is future
  work. We accept this audit cycle without dudect evidence.

## 10. Re-verification

After remediation we propose:

1. Maintainer lands the fixes.
2. Re-runs the auditor's recommended commands.
3. Vendor's named lead re-reviews the diff (4–8 hours billable).
4. Vendor issues a re-verification letter.

## 11. Contacts

Final on the contract exhibit. For reference:

* **Maintainer:** see `RFP-v1.0.md` §1.
* **Security-disclosure email:** see `SECURITY.md`.
* **Tracking issue:** [#177](https://github.com/sebastienrousseau/kyberlib/issues/177).
