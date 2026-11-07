# ADR 0002 — Quarantining SIMD `unsafe` into `kyberlib-asm`

* **Status:** Proposed (skeleton landed in v0.0.7 / phase 1.2; full move tracked in #143)
* **Date:** 2026-05-19
* **Stakeholders:** core maintainers; downstream consumers requiring `#![forbid(unsafe_code)]` provenance

## Context

The AVX2 acceleration path in `kyberlib` lives at `crates/kyberlib/src/avx2/`
and contains:

- ~13 Rust files using `core::arch::x86_64::*` intrinsics (55 `unsafe`
  blocks).
- 5 GAS (`*.S`) and 5 NASM (`*.asm`) hand-written assembly files.
- Compilation glue in `build.rs`.

This sits in the same crate as the safe reference implementation, which
prevents the safe core from carrying `#![forbid(unsafe_code)]` — a
requirement increasingly cited by enterprise consumers
(FedRAMP / EU CRA / supply-chain auditors).

## Problem

The avx2 module imports heavily from sibling modules in `kyberlib`:

```
use crate::params::*;
use crate::rng::randombytes;
use crate::symmetric::*;
use crate::reference::{poly, polyvec, fips202, ...};
```

A naive move into a new `kyberlib-asm` crate creates a dependency cycle:
`kyberlib-asm` would need `kyberlib`'s constants/rng/symmetric, but
`kyberlib` needs `kyberlib-asm` for the AVX2 code path.

## Options considered

### A — Status quo + cfg-gated `forbid`

Keep the AVX2 code in the safe crate. Add a `cfg_attr` so
`#![forbid(unsafe_code)]` is applied only when the `avx2` and `nasm`
features are off.

- **Pros:** Zero file moves. Default-feature builds (which most consumers
  ship) really do forbid unsafe.
- **Cons:** Users who opt in to AVX2 do *not* get a forbid-unsafe core.
  The supply-chain auditor reading the crate source still sees `unsafe`
  blocks.

### B — Three-crate split: `kyberlib-constants` + `kyberlib` + `kyberlib-asm`

Extract shared constants, parameters, RNG glue, and KeccakState types
into a new `kyberlib-constants` crate that both `kyberlib` and
`kyberlib-asm` depend on.

- **Pros:** Clean dependency graph. `kyberlib` and `kyberlib-asm` are
  truly independent of each other and each can `#![forbid(unsafe_code)]`
  / `#![allow(unsafe_code)]` independently.
- **Cons:** Three crates. Constants crate is small and may seem
  over-engineered. Adds one more thing to version-bump in lockstep.

### C — Trait-based split: `kyberlib` exposes `Backend` trait, `kyberlib-asm` implements it

Move only the leaf computational functions (NTT, basemul, poly_compress,
…) into the asm crate, expose them via a `Backend` trait. The safe core
holds the AAD layer and dispatches to the appropriate backend.

- **Pros:** Mirrors `libcrux`'s pattern. Lets us add `aws-lc` and
  `libcrux` backends symmetrically in phase 5.
- **Cons:** Big refactor. Requires designing the `Backend` trait
  surface. Each leaf function gets a trait-method indirection.

## Decision

**Combine A (now) and B (later):**

* Phase 1.2 (this commit): **Option A** — cfg-gated `forbid(unsafe_code)`
  in the safe core, plus a `kyberlib-asm` workspace skeleton with
  `publish = false`. The skeleton documents what's coming and pre-allocates
  the namespace so future moves don't introduce new crates.
* Phase 1.2 follow-up (issue #143): **Option B** — extract a
  `kyberlib-constants` crate that holds the parameter types, OID table,
  `KeccakState`, and the trait surface for `randombytes`. `kyberlib` and
  `kyberlib-asm` both depend on it. Once that lands, the AVX2 module
  actually moves into `kyberlib-asm` and the safe core
  unconditionally `#![forbid(unsafe_code)]`s.
* Phase 5 (issue #170 / #171): re-use the `kyberlib-constants` surface
  to add `aws-lc-rs` and `libcrux-ml-kem` as alternative backends —
  i.e. partial **Option C**, but only at the backend-selection layer,
  not inside the safe core.

## Consequences

- Default-features builds (no avx2, no nasm) honour
  `#![forbid(unsafe_code)]` today.
- Users who opt in to AVX2 will see "this is fine for now; will be
  cleaner after #143" in the crate docs.
- The workspace ships with `kyberlib-asm` as an empty skeleton —
  consumers checking the repo see "this is where it's going" rather
  than guessing.
- Phase 5 (FIPS / verified backends) has a coherent landing site.

## Verification

`cargo build -p kyberlib --no-default-features --features kyber768`
emits no warnings and `cargo expand --no-default-features --features kyber768`
shows zero `unsafe` blocks in the expanded source. `cargo geiger -p kyberlib`
should report 0/0/0/0/0 unsafe under the default-feature build (to be
added to CI once `cargo-geiger` is bumped past its current upstream
maintenance hiccup).
