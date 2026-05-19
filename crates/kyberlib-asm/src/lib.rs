// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-asm`
//!
//! Placeholder crate for the AVX2 / NEON / future SVE2 + AVX-512 assembly
//! acceleration backends of `kyberlib`. **Not yet usable.**
//!
//! ## Status
//!
//! The AVX2 source (Rust intrinsics + hand-written GAS/NASM assembly) still
//! lives at `crates/kyberlib/src/avx2/`. The eventual move into this crate
//! is tracked by issue [#143][i143]. The move is non-trivial because the
//! AVX2 module imports heavily from `crate::params::*`, `crate::rng`,
//! `crate::symmetric::*`, and `crate::reference::poly::*` — a clean split
//! requires either a shared `kyberlib-constants` crate or a re-export
//! surface from the safe core. That design decision is logged in
//! `doc/adr/0002-asm-quarantine.md` (filed alongside this commit).
//!
//! ## Why the skeleton lands now
//!
//! 1. So the workspace layout matches `noyalib`'s pattern from day one,
//!    making it easy to add `kyberlib-hybrid`, `kyberlib-pkcs8`,
//!    `kyberlib-wasm`, etc. without further restructuring.
//! 2. So `Cargo.lock` and CI workflows enumerate every workspace member
//!    we plan to ship — surprises during release are bad surprises.
//! 3. So consumers checking the crates.io page see "placeholder /
//!    upcoming" rather than wondering whether the AVX2 path is broken.
//!
//! In the meantime, the safe core (`kyberlib`) carries a cfg-gated
//! `#![forbid(unsafe_code)]`: the common build path (no `avx2` and no
//! `nasm` features) **does** forbid unsafe — only when the user
//! explicitly opts in to a SIMD backend is `unsafe` re-allowed.
//!
//! [i143]: https://github.com/sebastienrousseau/kyberlib/issues/143

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
