# Architecture

> Last Updated: 2026-05-22

`kyberlib-asm` is the planned home for `kyberlib`'s
machine-specific acceleration backends: AVX2 + GFNI on
x86_64, NEON on aarch64, SVE2 on aarch64 server parts, and
AVX-512 on x86_64-v4 Sapphire Rapids+. At v0.0.7 the crate
is a **skeleton** — its only purpose is to reserve the
crates.io name and document the boundary that will hold
the unsafe acceleration code once the source-relocation
work in [#143] lands.

## Why a sidecar crate

The audit-target safe core (`crates/kyberlib/`) carries
`#![forbid(unsafe_code)]` under default features. Every
`unsafe` block in the SIMD intrinsics + assembly
trampolines lives behind a `--features avx2` / `--features
nasm` gate. The gate already makes the safe-core property
hold (see [ADR 0002][adr2] and `crates/kyberlib/doc/safety.md`),
but the *file layout* still puts `unsafe` code under the
same crate root as the audit target — so a reviewer must
read `src/lib.rs`'s `#[cfg_attr(...)]` to know which lints
apply where.

Splitting the SIMD code into a separate crate moves that
property from "lint policy" to "filesystem layout". The
safe core's `Cargo.toml` no longer has *any* feature that
can lift `forbid(unsafe_code)`; consumers who want SIMD
acceleration depend on `kyberlib-asm` explicitly and the
boundary is visible in their dep graph.

## Future module map

```text
crates/kyberlib-asm/src/
├── lib.rs               re-exports + feature dispatch
├── x86_64/
│   ├── mod.rs
│   ├── avx2.rs          relocated from crates/kyberlib/src/avx2/
│   ├── gfni.rs          AES round constants via GFNI (future)
│   └── avx512.rs        VPMADD52 + VPCLMULQDQ kernels (future)
├── aarch64/
│   ├── mod.rs
│   ├── neon.rs          ARM NEON port (future)
│   └── sve2.rs          AWS Graviton 3+ port (future)
└── benches/
    └── per_backend.rs   throughput vs reference under matched
                         test vectors
```

Each backend is gated on a Cargo feature:

```toml
[features]
default = []
avx2    = []
avx512  = ["avx2"]
gfni    = ["avx2"]
neon    = []
sve2    = ["neon"]
```

Runtime dispatch happens once at crate-init via
`std::sync::OnceLock<Backend>` using `is_x86_feature_detected!`
/ `std::arch::is_aarch64_feature_detected!`. The picked
backend is then called via a function pointer; no
per-operation `cpuid` branch.

## Safety boundary

Every public function in `kyberlib-asm` will be `unsafe fn`
or `safe fn` wrapping an internal `unsafe` body — never a
safe re-export of raw SIMD intrinsics. The wrapping safe
function is responsible for:

* checking the runtime CPU-feature gate matches the
  compile-time gate (panics on mismatch, since this means
  a misconfigured caller),
* verifying length / alignment / non-aliasing invariants
  before entering the `unsafe` block,
* documenting the invariant the `unsafe` block relies on
  in a `// SAFETY:` comment immediately above the block.

This is the same pattern `crates/kyberlib/src/avx2/` uses
today. The relocation is mechanical; the safety contract
doesn't change.

## Why this isn't a `cfg(target_feature)` macro

A simpler design would have been to keep the SIMD code in
the core crate and gate everything on `cfg(target_feature
= "avx2")`. This was rejected because:

1. `target_feature` is a compile-time gate; AVX2 detection
   needs to happen at runtime to support `target-cpu=native`
   on heterogeneous CI fleets.
2. The cross-compilation matrix (compile on arm64 macOS
   targeting x86_64 Linux server) routinely picks up the
   wrong `cc` default. A separate crate makes the toolchain
   assumption explicit at the crate boundary, so a broken
   cross-compile fails at `cargo build` rather than at
   `cargo test`.
3. crates.io discoverability: `kyberlib-asm 0.0.7` on
   crates.io advertises SIMD acceleration as a first-class
   option. Burying it behind a feature flag is harder for
   downstream consumers to find.

## Current status

* `publish = false` — the crate is not yet on crates.io.
* `src/lib.rs` is `#![no_std] + #![forbid(unsafe_code)]` +
  an `assert_eq!(1+1, 2)` placeholder unit test, so the
  skeleton compiles cleanly under the workspace lints.
* The actual relocation is tracked by [#143] and gated on
  Phase 1.2 of `PLAN.md`.

See [`roadmap.md`](./roadmap.md) for the detailed work
plan.

[#143]: https://github.com/sebastienrousseau/kyberlib/issues/143
[adr2]: ../../../doc/adr/0002-asm-quarantine.md
