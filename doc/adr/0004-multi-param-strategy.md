# ADR 0004 — Multi-parameter-set strategy for ML-KEM

* **Status:** Accepted (partial implementation landed in v0.0.7; #130c tracks the final lift)
* **Date:** 2026-05-19
* **Authors:** sebastienrousseau
* **Tracking issue:** [#130b](https://github.com/sebastienrousseau/kyberlib/issues/130) / [#130c](https://github.com/sebastienrousseau/kyberlib/issues/130) (follow-up)

## Context

FIPS 203 defines three parameter sets — ML-KEM-512, ML-KEM-768,
ML-KEM-1024 — distinguished by their module rank `k` (2, 3, 4
respectively). Each has its own ek/dk/ct/ss byte sizes. CNSA 2.0
mandates ML-KEM-1024 for some workloads, ML-KEM-768 is the
TLS-default, and ML-KEM-512 ships in IoT / constrained-resource
deployments.

A v1.0 kyberlib must support all three. The question is *how*.

## State as of this commit (v0.0.7, Phase 3a)

The public API has:

* **Marker types** for all three: `MlKem512`, `MlKem768`,
  `MlKem1024` — each declared in `crates/kyberlib/src/ml_kem.rs`,
  sealed, with the FIPS 203 sizes hard-coded as inherent
  associated constants (`K`, `PUBLIC_KEY_BYTES`, `SECRET_KEY_BYTES`,
  `CIPHERTEXT_BYTES`, `OID`, `ALGORITHM_ID`).
* **Typed wrappers** for all three sets, sized per FIPS 203
  Table 2: `MlKem{512,768,1024}{EncapKey,DecapKey,Ciphertext}`.
  All three carry `from_bytes` / `try_from_slice` / `as_bytes` /
  redacted `Debug` impls + `Zeroize` + `ZeroizeOnDrop` on the
  decapsulation keys.
* **`KemCore` trait impl** on `MlKem768` only. `MlKem512` and
  `MlKem1024` are sealed-trait `Sealed` members but do **not**
  implement `KemCore` yet — calling `KemCore::generate` on them is
  a compile error.

The underlying primitives in `crates/kyberlib/src/reference/`
(`indcpa_keypair`, `indcpa_enc`, `indcpa_dec`, `gen_matrix`,
`poly_compress`, `polyvec_compress`, …) are parameterised by the
global `KYBER_SECURITY_PARAMETER` constant, which is `cfg(feature
= "kyber*")`-gated. **Only one parameter set is reachable per build.**

## Problem

A consumer who imports `MlKem512EncapKey` today gets the right
*type* — the array is 800 bytes — but cannot actually run
`MlKem512::generate` because there is no `KemCore` impl. The
follow-up that flips that switch is the "multi-parameter-set
lift" (#130c).

The lift is technically non-trivial because:

1. Every primitive function in `reference/` uses the
   global `KYBER_SECURITY_PARAMETER` and `KYBER_*_BYTES` constants
   directly. Removing the `cfg`-gating requires the primitives to
   be **parameterised at the type level** by the module rank `k`.
2. Several intermediate buffers have sizes computed from `k`:
   the `gen_matrix` rejection-sampling buffer, the `polyvec`
   storage, the `indcpa_keypair` matrix `[Polyvec; k]`. In Rust
   stable, `[T; k]` where `k` is a const-generic parameter is
   allowed; but `[T; 12 * k * 256 / 8]` (the rejection-sampling
   buffer size) requires `feature(generic_const_exprs)` which is
   nightly-only.
3. The MSRV of v0.0.7 is 1.74. Nightly-only features are not
   acceptable in the safe core.

## Options considered

### A — Full const-generic refactor with `generic_const_exprs`

Use `<const K: usize>` everywhere and the computed array sizes
directly. Requires `feature(generic_const_exprs)` for the
indirect-size arrays.

- **Pros:** Cleanest possible source; matches FIPS 203's `k`-
  parameter naming; zero runtime overhead vs. status quo.
- **Cons:** Nightly-only. We'd have to either flip the safe core
  to nightly (unacceptable for an enterprise crypto crate that
  ships to FIPS-track customers) or back-port via the
  `hybrid-array` crate's `Array<T, U>` type-number trick. The
  latter is what `RustCrypto/ml-kem` does — it's a real lift.

### B — Module-per-parameter-set via macro

A `make_kem!(K = N, ETA1 = N, …)` macro that expands the entire
primitive surface three times, producing `ml_kem_512`,
`ml_kem_768`, `ml_kem_1024` modules each with its own constants
and primitive functions. Mirrors how pq-crystals' C reference is
laid out (separate object files per parameter set).

- **Pros:** MSRV-friendly; no `Vec`s in the hot path; each
  parameter set's binary has only the right-sized code.
- **Cons:** ~2x source-tree size; macros that generate ~700 LoC
  each are hard to debug; clippy / Miri / rustdoc / fuzzing have
  to grok the expanded source.

### C — Type-level associated constants + `Vec<T>` for variable buffers

Define `KemParams` trait with associated consts; pass a marker
type to every primitive. Use `Vec<T>` for buffers whose size
depends on `K`.

- **Pros:** Smallest source diff; MSRV-friendly; the Vec
  allocations happen once per keygen, not per-coefficient.
- **Cons:** Drops `no_std` purity (we'd need `alloc`); ~1-2%
  runtime overhead per primitive call from the heap allocations;
  Miri runs slower with `Vec`.

### D — `RustCrypto/hybrid-array` adopt the same trick

Use `Array<T, N: ArraySize>` with `ArraySize` implementations for
the specific sizes we care about. This is option A with a stable
workaround.

- **Pros:** Stable MSRV; idiomatic in the RustCrypto ecosystem;
  what the established competitor does.
- **Cons:** Adds `hybrid-array` (and transitively `typenum`) as a
  hard dependency. Modest but visible audit surface increase.

## Decision

Stage the lift over **two follow-up phases**:

* **#130b (this commit, Phase 3a-bis):** ship the **typed surface**
  for all three parameter sets — `MlKemX::PUBLIC_KEY_BYTES`-style
  associated consts and `MlKemXEncapKey`/`MlKemXDecapKey`/`MlKemXCiphertext`
  wrappers. Downstream code can be written today against the full
  matrix. `MlKem768` implements `KemCore`; the other two don't.

* **#130c (Phase 3b, next milestone):** apply **Option D** — adopt
  `hybrid-array` and refactor the primitives to be generic over a
  `KemParams` trait. Implement `KemCore` for all three markers.
  Single build supports all three. ACVP harness flips from
  60 / 60 → 240 / 240. Add `hybrid-array` to `supply-chain/audits.toml`
  (it's already in the RustCrypto trusted-import set).

Rationale for Option D over Option B:

1. The audit surface (`hybrid-array` + `typenum`) is well-trodden;
   RustCrypto uses it pervasively and it's covered by our cargo-vet
   imports.
2. The source-tree size growth from Option B (macro-expanded
   per-set modules) imposes a higher long-term maintenance cost
   than one extra crate dep.
3. Matches the convention established by `RustCrypto/ml-kem` and
   `libcrux-ml-kem` — consumers fluent in the ecosystem expect
   `Array<u8, U800>` for ML-KEM-512 EncapKey rather than
   `[u8; 800]`.

## Consequences

### Positive

* Downstream code can be written today against
  `MlKemX::PUBLIC_KEY_BYTES` and the typed wrappers.
* The eventual lift in #130c does not require breaking the public
  API surface (the trait shape is the same).
* The `KemCore` trait stays sealed and stable across the lift.

### Negative

* `MlKem512` and `MlKem1024` `KemCore` impls remain pending until
  #130c lands. Consumers who want runnable ML-KEM-512 or
  ML-KEM-1024 today have to either:
  - rebuild kyberlib with `--features kyber512` or
    `--features kyber1024` (after uncommenting them in
    `crates/kyberlib/Cargo.toml`) — only one set per build, only
    `MlKem768::generate` returns the *right* sized output for the
    feature in effect; or
  - wait for #130c.
* The typed wrappers in this commit are slightly more code than
  strictly necessary, but the convenience of letting downstream
  consumers reference `MlKem512EncapKey::from_bytes(...)` today
  outweighs the cost.

### Neutral

* ACVP harness coverage stays at 60 / 60 ML-KEM-768 in this
  commit. #130c will flip it to 240 / 240.

## References

* FIPS 203 §6: parameter-set table.
* `RustCrypto/hybrid-array` —
  <https://github.com/RustCrypto/hybrid-array>
* `RustCrypto/ml-kem` source (for prior-art on the same problem) —
  <https://github.com/RustCrypto/KEMs/tree/master/ml-kem>
* `libcrux-ml-kem` const-generic approach —
  <https://github.com/cryspen/libcrux/tree/main/libcrux-ml-kem>
