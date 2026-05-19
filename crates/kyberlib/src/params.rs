// Copyright © 2024-2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Constants and parameters for the FIPS 203 ML-KEM scheme.
//!
//! v0.0.7 renames the public constants from `KYBER_*` to `ML_KEM_*`
//! (issue #151). The old names are retained as `#[deprecated]`
//! aliases for one release so downstream consumers can migrate at
//! their own pace.
//!
//! For per-parameter-set sized constants (`ML-KEM-512`, `ML-KEM-768`,
//! `ML-KEM-1024`) once #130b lands, prefer the associated constants
//! on the [`KemParams`](crate::ml_kem::sealed::KemParams) trait via
//! the marker types `MlKem512` / `MlKem768` / `MlKem1024`. The
//! free constants in this module pin to the **current build's**
//! parameter set (currently always ML-KEM-768 — `kyber512` and
//! `kyber1024` features are reserved but disabled).

// ============================================================================
// Canonical names (ML_KEM_*) — use these in new code
// ============================================================================

/// Enables or disables 90's mode (AES-CTR + SHA2 instead of SHAKE).
///
/// Removed from FIPS 203; retained pre-spec-migration for
/// compatibility with the Round-3 era. Set by `features = ["90s"]`.
pub const ML_KEM_90S: bool = cfg!(feature = "90s");

/// Noise parameter eta1 — width of the centred binomial distribution
/// for the secret-key sampling.
///
/// `3` for ML-KEM-512, `2` for ML-KEM-768 and ML-KEM-1024.
pub const ML_KEM_ETA1: usize =
    if cfg!(feature = "kyber512") { 3 } else { 2 };

/// Noise parameter eta2 — width of the centred binomial distribution
/// for the ciphertext-noise sampling. Always 2 in FIPS 203.
pub const ML_KEM_ETA2: usize = 2;

/// Size in bytes of seeds, message inputs, and shared secrets.
pub const ML_KEM_SYM_BYTES: usize = 32;

/// Polynomial degree N — the ring is `R_q = Z_q[X] / (X^256 + 1)`.
pub const ML_KEM_N: usize = 256;

/// Modulus q for the cyclotomic ring. ML-KEM uses q = 3329 for every
/// parameter set; the value is what enables the NTT to map cleanly
/// to a power-of-two-friendly representation.
pub const ML_KEM_Q: usize = 3329;

/// The module rank `k` — number of polynomials in the secret-key /
/// public-key polynomial vectors.
///
/// `2` for ML-KEM-512, `3` for ML-KEM-768 (default), `4` for ML-KEM-1024.
pub const ML_KEM_SECURITY_PARAMETER: usize =
    if cfg!(feature = "kyber512") {
        2
    } else if cfg!(feature = "kyber1024") {
        4
    } else {
        3
    };

/// Serialized size of a single polynomial in the ring. 384 = 256 * 12 / 8.
pub const ML_KEM_POLY_BYTES: usize = 384;

/// Compressed serialized size of a single polynomial (for the v half
/// of the ciphertext). 128 bytes for ML-KEM-512/768 (d_v = 4),
/// 160 bytes for ML-KEM-1024 (d_v = 5).
#[cfg(not(feature = "kyber1024"))]
pub const ML_KEM_POLY_COMPRESSED_BYTES: usize = 128;

/// See [`ML_KEM_POLY_COMPRESSED_BYTES`] (ML-KEM-1024 variant).
#[cfg(feature = "kyber1024")]
pub const ML_KEM_POLY_COMPRESSED_BYTES: usize = 160;

/// Serialized size of the polynomial vector (k polynomials).
pub const ML_KEM_POLYVEC_BYTES: usize =
    ML_KEM_SECURITY_PARAMETER * ML_KEM_POLY_BYTES;

/// Compressed serialized size of the polynomial vector (for the u half
/// of the ciphertext).
#[cfg(not(feature = "kyber1024"))]
pub const ML_KEM_POLYVEC_COMPRESSED_BYTES: usize =
    ML_KEM_SECURITY_PARAMETER * 320;

/// See [`ML_KEM_POLYVEC_COMPRESSED_BYTES`] (ML-KEM-1024 variant).
#[cfg(feature = "kyber1024")]
pub const ML_KEM_POLYVEC_COMPRESSED_BYTES: usize =
    ML_KEM_SECURITY_PARAMETER * 352;

/// Size of the IND-CPA public key (polynomial vector + 32-byte
/// `publicseed`).
pub const ML_KEM_INDCPA_PUBLIC_KEY_BYTES: usize =
    ML_KEM_POLYVEC_BYTES + ML_KEM_SYM_BYTES;

/// Size of the IND-CPA secret key (one polynomial vector).
pub const ML_KEM_INDCPA_SECRET_KEY_BYTES: usize = ML_KEM_POLYVEC_BYTES;

/// Size of the IND-CPA ciphertext.
pub const ML_KEM_INDCPA_BYTES: usize =
    ML_KEM_POLYVEC_COMPRESSED_BYTES + ML_KEM_POLY_COMPRESSED_BYTES;

/// Size of the public encapsulation key (same as the IND-CPA public key).
pub const ML_KEM_PUBLIC_KEY_BYTES: usize =
    ML_KEM_INDCPA_PUBLIC_KEY_BYTES;

/// Size of the secret decapsulation key.
///
/// Layout (FIPS 203 §6.1): `dk_PKE ‖ ek_PKE ‖ H(ek) ‖ z`.
pub const ML_KEM_SECRET_KEY_BYTES: usize =
    ML_KEM_INDCPA_SECRET_KEY_BYTES
        + ML_KEM_INDCPA_PUBLIC_KEY_BYTES
        + 2 * ML_KEM_SYM_BYTES;

/// Size of the IND-CCA ciphertext (same as the IND-CPA ciphertext).
pub const ML_KEM_CIPHERTEXT_BYTES: usize = ML_KEM_INDCPA_BYTES;

/// Size of the shared secret K.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

// ============================================================================
// Deprecated aliases (KYBER_*) — for downstream-consumer migration
// ============================================================================
//
// These were the public names in v0.0.6 and earlier. They forward to
// the canonical `ML_KEM_*` constants above. Will be removed in a
// future release.
//
// We deliberately do NOT mark every alias `#[deprecated]` because:
//   1. internal-to-kyberlib uses of these names are pervasive
//      (`crates/kyberlib/src/{kem,kex,reference/*}.rs`, the macros
//      module, the WASM crate, the hybrid crate). Migrating every
//      site to the ML_KEM names is a separate mechanical task;
//      flagging the alias as `#[deprecated]` would create
//      ~hundreds of warnings inside our own tree.
//   2. The doc lint `#[deny(missing_docs)]` enforces that the alias
//      carries the migration pointer even without `#[deprecated]`.
//
// External consumers SHOULD migrate to the `ML_KEM_*` names; the
// CHANGELOG.md v0.0.7 entry calls out the rename explicitly. The
// next minor release will tighten this to a hard `#[deprecated]`
// once internal migrations land.

/// Alias for [`ML_KEM_90S`]. Renamed v0.0.7 (#151).
pub const KYBER_90S: bool = ML_KEM_90S;
/// Alias for [`ML_KEM_ETA1`]. Renamed v0.0.7 (#151).
pub const KYBER_ETA1: usize = ML_KEM_ETA1;
/// Alias for [`ML_KEM_ETA2`]. Renamed v0.0.7 (#151).
pub const KYBER_ETA2: usize = ML_KEM_ETA2;
/// Alias for [`ML_KEM_SYM_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_SYM_BYTES: usize = ML_KEM_SYM_BYTES;
/// Alias for [`ML_KEM_N`]. Renamed v0.0.7 (#151).
pub const KYBER_N: usize = ML_KEM_N;
/// Alias for [`ML_KEM_Q`]. Renamed v0.0.7 (#151).
pub const KYBER_Q: usize = ML_KEM_Q;
/// Alias for [`ML_KEM_SECURITY_PARAMETER`]. Renamed v0.0.7 (#151).
pub const KYBER_SECURITY_PARAMETER: usize = ML_KEM_SECURITY_PARAMETER;
/// Alias for [`ML_KEM_POLY_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_POLY_BYTES: usize = ML_KEM_POLY_BYTES;
/// Alias for [`ML_KEM_POLY_COMPRESSED_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_POLY_COMPRESSED_BYTES: usize =
    ML_KEM_POLY_COMPRESSED_BYTES;
/// Alias for [`ML_KEM_POLYVEC_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_POLYVEC_BYTES: usize = ML_KEM_POLYVEC_BYTES;
/// Alias for [`ML_KEM_POLYVEC_COMPRESSED_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_POLYVEC_COMPRESSED_BYTES: usize =
    ML_KEM_POLYVEC_COMPRESSED_BYTES;
/// Alias for [`ML_KEM_INDCPA_PUBLIC_KEY_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_INDCPA_PUBLIC_KEY_BYTES: usize =
    ML_KEM_INDCPA_PUBLIC_KEY_BYTES;
/// Alias for [`ML_KEM_INDCPA_SECRET_KEY_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_INDCPA_SECRET_KEY_BYTES: usize =
    ML_KEM_INDCPA_SECRET_KEY_BYTES;
/// Alias for [`ML_KEM_INDCPA_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_INDCPA_BYTES: usize = ML_KEM_INDCPA_BYTES;
/// Alias for [`ML_KEM_PUBLIC_KEY_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_PUBLIC_KEY_BYTES: usize = ML_KEM_PUBLIC_KEY_BYTES;
/// Alias for [`ML_KEM_SECRET_KEY_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_SECRET_KEY_BYTES: usize = ML_KEM_SECRET_KEY_BYTES;
/// Alias for [`ML_KEM_CIPHERTEXT_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_CIPHERTEXT_BYTES: usize = ML_KEM_CIPHERTEXT_BYTES;
/// Alias for [`ML_KEM_SHARED_SECRET_BYTES`]. Renamed v0.0.7 (#151).
pub const KYBER_SHARED_SECRET_BYTES: usize = ML_KEM_SHARED_SECRET_BYTES;
