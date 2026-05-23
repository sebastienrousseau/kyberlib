// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-asm`
//!
//! Placeholder for the future AVX2 / NEON / SVE2 / AVX-512 assembly
//! backends of `kyberlib`. **Not yet usable as a dependency.**
//!
//! ## Status (v0.0.7)
//!
//! The AVX2 source (Rust intrinsics + hand-written GAS / NASM
//! assembly) still lives at `crates/kyberlib/src/avx2/`. The
//! cross-crate move is tracked by issue [#143][i143].
//!
//! However, **the safety property the move was meant to provide has
//! already landed** via a finer-grained lint gate in
//! `crates/kyberlib/src/lib.rs`:
//!
//! ```text
//!   Default (no avx2, no nasm) → #![forbid(unsafe_code)]
//!   With --features avx2/nasm  → #![deny(unsafe_code)] crate-wide
//!                                + #[allow(unsafe_code)] on `mod avx2;` only
//! ```
//!
//! The safe-core modules (`api`, `kex`, `kem`, `ml_kem`, `params`,
//! `rng`, `symmetric`, `oid`, `error`) inherit the crate-level
//! `deny` under every feature combination — they are unsafe-free
//! even under `--features avx2`. Only the `avx2` module itself can
//! hold the SIMD intrinsics + assembly trampolines.
//!
//! ## Why the source move is still tracked
//!
//! 1. **Build hygiene** — AVX2 cross-compilation is broken on hosts
//!    whose default `cc` target doesn't match (e.g. arm64 macOS
//!    without an explicit `--target x86_64-...` switch). Moving into
//!    a separate crate makes the SIMD-backend toolchain assumptions
//!    explicit at the crate boundary.
//! 2. **Workspace shape** — matches the noyalib pattern (safe core +
//!    asm sidecar + WASM sidecar + hybrid sidecar). Easier to add
//!    NEON and AVX-512 backends as sibling crates.
//! 3. **crates.io discoverability** — `kyberlib-asm 0.0.7` on
//!    crates.io would advertise SIMD acceleration as a first-class
//!    option rather than burying it in a feature flag.
//!
//! [i143]: https://github.com/sebastienrousseau/kyberlib/issues/143

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
