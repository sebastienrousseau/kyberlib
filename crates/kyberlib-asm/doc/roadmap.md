# Roadmap

Tracking the multi-phase work to take `kyberlib-asm` from
the v0.0.7 skeleton to a publishable acceleration crate.
See [`architecture.md`](./architecture.md) for the design
target; this file is the chronological plan.

## Phase A — relocate AVX2 (issue [#143])

Mechanical move of `crates/kyberlib/src/avx2/` and its
`assembly/` sibling into `crates/kyberlib-asm/src/x86_64/`.
No functional changes.

Tasks:

1. Move `crates/kyberlib/src/avx2/*.rs` → `crates/kyberlib-asm/src/x86_64/`.
2. Move `crates/kyberlib/src/avx2/assembly/*.S` (and any
   `.asm` siblings) → `crates/kyberlib-asm/asm/x86_64/`.
3. Move the `build.rs` shim that drives `cc` for the
   assembly into `crates/kyberlib-asm/build.rs`.
4. Replace the cfg-gated `mod avx2;` in
   `crates/kyberlib/src/lib.rs` with an `optional`
   dependency on `kyberlib-asm` and a re-export.
5. Flip `publish = false` → `publish = true`.
6. Verify the public-surface byte stream matches the
   pre-move bench:
   ```sh
   cargo bench --bench kyber_768 --baseline pre-move
   ```
7. CI: add a separate AVX2 build matrix job (currently
   skipped because of cc cross-compile breakage on default
   runners).

Exit criteria: ACVP 180/180 still green, public byte
stream unchanged, `kyberlib --features asm` route to the
new sidecar without touching the safe core.

## Phase B — NEON port (Apple Silicon + AWS Graviton 2)

Port the AVX2 intrinsics in `polyvec_compress`,
`poly_compress`, `polyvec_basemul_acc_montgomery`, and the
NTT to ARM NEON.

Reference: [`pq-crystals/kyber`][upstream] has a NEON port
in its `Round3/avx2-neon/` branch. Don't blind-copy —
NEON's 128-bit vector width changes the lane layout, so
the const tables and shuffle masks need to be re-derived.

Tasks:

1. Vector-width abstraction in `kyberlib-asm`'s public
   surface — `Vec128` vs `Vec256` chosen at compile time.
2. NEON port of the seven hot kernels.
3. Cross-arch CT bench: run the dudect harness on Graviton
   3 (c7g.large) under `target-cpu=neoverse-n1`.
4. NIST ACVP 180/180 conformance.

Exit criteria: ARM CI job green; Graviton 3 throughput
within 1.5× of x86_64-v3 AVX2 on equivalent silicon.

## Phase C — AVX-512 (Sapphire Rapids+)

Two backends: AVX-512BW (the bitwise + integer 512-bit
form) and AVX-512 IFMA (VPMADD52, for the Barrett
multiplier).

Tasks:

1. VPMADD52-driven Barrett kernel for the polynomial
   multiply chain.
2. VPCLMULQDQ-accelerated GHASH for the
   AES-256-GCM-bundled `kyberlib-hybrid` path.
3. Runtime dispatch: pick AVX-512 IFMA only when
   `is_x86_feature_detected!("avx512ifma")`.

Exit criteria: 1.5× speedup over AVX2 on Sapphire Rapids
keypair + decap; dudect t-statistic still under ±10σ.

## Phase D — SVE2 (Graviton 4 + Neoverse V2)

SVE2 is variable vector width (128–2048 bits) decided at
runtime. The ML-KEM kernels are well-suited because the
polynomial degree (256) and the modulus (3329) both fit
in the 16-bit lane width that SVE2 expresses naturally.

Tasks:

1. Vector-length-agnostic NTT loop.
2. ACVP 180/180 conformance on Graviton 4 (c8g).
3. Compare wall-clock vs the NEON port from Phase B.

## Phase E — formal verification interop

Provide a `--features verified` route that bypasses
`kyberlib-asm` entirely and delegates to
[`libcrux-ml-kem`][libcrux]'s F\* + hax-verified backend.
This is *parallel to* the speed work above, not a
replacement: verified code is portable Rust, ~3× slower
than AVX2 but with proven panic-freedom + secret-
independence.

The user picks at compile time: speed (`kyberlib-asm` AVX2
/ NEON / AVX-512 / SVE2) vs proof (`libcrux-ml-kem`).

Tasks:

1. Add `libcrux-ml-kem` as an optional dependency on the
   core crate.
2. Wire `MlKem768::generate` / `encapsulate` /
   `decapsulate` under `--features verified` to delegate.
3. CI: a verification matrix job confirms the verified
   backend still round-trips the ACVP vectors.

## Out of scope

* **Constant-time RSA** — not part of this crate.
* **CMVP / FIPS 140-3 validation** — covered separately
  via [#170]; the validation target is `aws-lc-rs`'s
  ML-KEM, not `kyberlib-asm`.
* **AVX2 fork into a no_std-only crate** — the existing
  `kyberlib` already has `--no-default-features` so this
  isn't a separate concern.

[#143]: https://github.com/sebastienrousseau/kyberlib/issues/143
[#170]: https://github.com/sebastienrousseau/kyberlib/issues/170
[upstream]: https://github.com/pq-crystals/kyber
[libcrux]: https://github.com/cryspen/libcrux
