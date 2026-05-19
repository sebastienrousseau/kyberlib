// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-hybrid`
//!
//! Hybrid post-quantum + classical KEMs built on `kyberlib`. Per
//! `draft-ietf-tls-ecdhe-mlkem-04` (TLS hybrid KEMs, Feb 2026) and the
//! IETF hybrid KEM design `draft-ietf-tls-hybrid-design-16`:
//!
//! | Name                  | TLS codepoint | Classical | Post-quantum    |
//! |-----------------------|---------------|-----------|-----------------|
//! | `X25519MlKem768`      | `0x11EC`      | X25519    | ML-KEM-768      |
//! | `SecP256r1MlKem768`   | `0x11EB`      | NIST P-256| ML-KEM-768      |
//! | `SecP384r1MlKem1024`  | `0x11ED`      | NIST P-384| ML-KEM-1024     |
//!
//! ## Wire format (X25519MlKem768)
//!
//! For the *client* share:
//!
//! ```text
//!   share := ML-KEM-768.EncapKey (1184 B) || X25519 share (32 B)  = 1216 B
//! ```
//!
//! For the *server* share (response), the order reverses:
//!
//! ```text
//!   share := X25519 share (32 B) || ML-KEM-768.Ciphertext (1088 B) = 1120 B
//! ```
//!
//! The shared secret is the concatenation `ML-KEM-768.SharedSecret ||
//! X25519.SharedSecret`, passed through TLS 1.3's HKDF.
//!
//! ## Status
//!
//! **Skeleton only.** Three reasons we hold off on a full
//! implementation:
//!
//! 1. **kyberlib is currently Kyber Round 3, not FIPS 203 ML-KEM**
//!    (see commit `d6ded86`, the ACVP harness, and issue #147).
//!    Shipping a hybrid that wraps a non-FIPS-203 KEM would produce
//!    bytes that won't interop with any other TLS endpoint and would
//!    mislead consumers about the security level. Phase 2(b) closes
//!    that gap.
//!
//! 2. **The X25519 dependency is non-trivial.** Pure-Rust X25519
//!    (`x25519-dalek` v3) requires extra audit work to fold into the
//!    cargo-vet exemptions, and the choice between `x25519-dalek`,
//!    `ed25519-dalek`'s X25519 path, and `curve25519-dalek` raw
//!    needs a deliberate decision — see issue #167 for the design
//!    discussion.
//!
//! 3. **ECDHE variants `SecP256r1MLKEM768` / `SecP384r1MLKEM1024`
//!    require an additional dependency choice** (RustCrypto's `p256`/
//!    `p384` vs `ring`-backed ECDH). Tracked under #167 part b.
//!
//! Until phase 2(b) lands, this crate exposes only the type-level
//! scaffold: the `Hybrid` trait, the `X25519MlKem768` /
//! `SecP256r1MlKem768` / `SecP384r1MlKem1024` marker types, and the
//! wire-format size constants. Calling any method panics with a
//! pointer to issue #167.

#![cfg_attr(not(feature = "x25519"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Combined-share wire-format sizes per `draft-ietf-tls-ecdhe-mlkem-04`.
pub mod sizes {
    /// Client share for `X25519MlKem768`: ML-KEM-768 EncapKey || X25519 share.
    pub const X25519_MLKEM768_CLIENT_SHARE: usize = 1184 + 32;
    /// Server share for `X25519MlKem768`: X25519 share || ML-KEM-768 Ciphertext.
    pub const X25519_MLKEM768_SERVER_SHARE: usize = 32 + 1088;
    /// Combined shared secret length (ML-KEM-768.SS || X25519.SS).
    pub const X25519_MLKEM768_SHARED_SECRET: usize = 32 + 32;
}

/// Marker trait for hybrid KEM constructions. The concrete types
/// `X25519MlKem768`, `SecP256r1MlKem768`, `SecP384r1MlKem1024` will
/// implement this once phase 2(b) lands the FIPS 203 patches.
///
/// See issue #167 for the design discussion.
pub trait Hybrid: sealed::Sealed {
    /// IETF codepoint per the TLS NamedGroup registry.
    const TLS_CODEPOINT: u16;
    /// Combined client-share length (PQ public + classical share).
    const CLIENT_SHARE_LEN: usize;
    /// Combined server-share length (classical share + PQ ciphertext).
    const SERVER_SHARE_LEN: usize;
    /// Combined shared-secret length.
    const SHARED_SECRET_LEN: usize;
}

/// Sealed pattern — only this crate implements `Hybrid`.
mod sealed {
    /// Sealing trait for the hybrid KEM marker types.
    pub trait Sealed {}
}

/// X25519 + ML-KEM-768 hybrid (TLS codepoint `0x11EC`).
#[cfg(feature = "x25519")]
#[derive(Clone, Copy, Debug)]
pub struct X25519MlKem768;

#[cfg(feature = "x25519")]
impl sealed::Sealed for X25519MlKem768 {}

#[cfg(feature = "x25519")]
impl Hybrid for X25519MlKem768 {
    const TLS_CODEPOINT: u16 = 0x11EC;
    const CLIENT_SHARE_LEN: usize = sizes::X25519_MLKEM768_CLIENT_SHARE;
    const SERVER_SHARE_LEN: usize = sizes::X25519_MLKEM768_SERVER_SHARE;
    const SHARED_SECRET_LEN: usize = sizes::X25519_MLKEM768_SHARED_SECRET;
}

/// SecP256r1 + ML-KEM-768 hybrid (TLS codepoint `0x11EB`).
#[cfg(feature = "secp256r1")]
#[derive(Clone, Copy, Debug)]
pub struct SecP256r1MlKem768;

#[cfg(feature = "secp256r1")]
impl sealed::Sealed for SecP256r1MlKem768 {}

#[cfg(feature = "secp256r1")]
impl Hybrid for SecP256r1MlKem768 {
    const TLS_CODEPOINT: u16 = 0x11EB;
    const CLIENT_SHARE_LEN: usize = 1184 + 65; // P-256 uncompressed point = 65 B
    const SERVER_SHARE_LEN: usize = 65 + 1088;
    const SHARED_SECRET_LEN: usize = 32 + 32;
}

/// SecP384r1 + ML-KEM-1024 hybrid (TLS codepoint `0x11ED`).
#[cfg(feature = "secp384r1")]
#[derive(Clone, Copy, Debug)]
pub struct SecP384r1MlKem1024;

#[cfg(feature = "secp384r1")]
impl sealed::Sealed for SecP384r1MlKem1024 {}

#[cfg(feature = "secp384r1")]
impl Hybrid for SecP384r1MlKem1024 {
    const TLS_CODEPOINT: u16 = 0x11ED;
    const CLIENT_SHARE_LEN: usize = 1568 + 97; // P-384 uncompressed point = 97 B
    const SERVER_SHARE_LEN: usize = 97 + 1568;
    const SHARED_SECRET_LEN: usize = 32 + 48;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "x25519")]
    fn x25519_mlkem768_codepoint() {
        assert_eq!(X25519MlKem768::TLS_CODEPOINT, 0x11EC);
        assert_eq!(X25519MlKem768::CLIENT_SHARE_LEN, 1216);
        assert_eq!(X25519MlKem768::SERVER_SHARE_LEN, 1120);
        assert_eq!(X25519MlKem768::SHARED_SECRET_LEN, 64);
    }
}
