# ADR 0009 — Remove the AVX2 backend; delegate SIMD to libcrux

* **Status:** Accepted (v0.0.16)
* **Date of decision:** 2026-11-07
* **Authors:** sebastienrousseau
* **Tracking issue:** [#143](https://github.com/sebastienrousseau/kyberlib/issues/143)
* **Supersedes:** [ADR 0002](./0002-asm-quarantine.md)

## Context

kyberlib carried an x86_64 AVX2 backend (`crates/kyberlib/src/avx2/`:
Rust intrinsics, five GAS and five NASM assembly files, a build script)
behind the `avx2` and `nasm` features, plus an empty `kyberlib-asm` crate
meant to receive it (#143, ADR 0002).

That backend never compiled. Its IND-CPA layer has called
`poly_getnoise_eta1`, which the AVX2 `poly` module never defined, and
`indcpa_enc` has used an undefined matrix `a`, since the first commit
(2023-11-20). No CI job built the feature. A job added in v0.0.15 to run
NIST ACVP against it failed with 20 compile errors (CI run 42357137681);
its key generation also lacked the FIPS 203 domain-separation byte.
Making it work meant writing the missing layer, applying the FIPS 203
changes and testing on x86_64 only (Rosetta 2 exposes no AVX2), for a
body of `unsafe` code an auditor would have to review.

libcrux-ml-kem already ships portable, AVX2 and NEON ML-KEM backends,
verified with F\* and hax, and kyberlib reserves a `verified` feature for
it (#171).

## Decision

Remove the AVX2 backend, its build script and its `cc` / `nasm-rs`
build dependencies, the `avx2` and `nasm` features, and the `kyberlib-asm`
crate. The core crate is `#![forbid(unsafe_code)]` in every build. SIMD
speed, on x86_64 and AArch64, comes from the libcrux backend (#171, #172).

## Consequences

* `--features avx2` / `nasm` no longer exist. They never compiled, so no
  working build loses anything; a manifest that names them now fails at
  dependency resolution instead of at compile time.
* The safe-core guarantee is unconditional: no feature lifts
  `forbid(unsafe_code)`.
* Less code to maintain and audit: about 3,300 lines of Rust and 1,600 of
  assembly are gone.
* Until #171 lands, kyberlib has no SIMD path; the pure-Rust code is what
  ships, as it always was.

## Alternatives considered

* **Write the AVX2 backend.** Several iterations of unsafe SIMD code,
  testable only on x86_64 CI, duplicating what libcrux already provides
  with formal verification. Rejected.
* **Remove it with no SIMD plan.** Rejected in favour of tying SIMD to
  the libcrux backend.
