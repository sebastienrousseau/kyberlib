// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-pkcs8`
//!
//! PKCS#8 `PrivateKeyInfo`, `SubjectPublicKeyInfo`, and PEM encoding
//! for kyberlib's ML-KEM key material. Per the IETF LAMPS drafts:
//!
//! * `draft-ietf-lamps-kyber-certificates` — algorithm identifiers and
//!   X.509 conventions for ML-KEM public keys.
//! * `draft-ietf-lamps-cms-kyber` — ML-KEM in CMS (RFC 9936).
//!
//! ## OID table
//!
//! | Algorithm    | OID                       |
//! |--------------|---------------------------|
//! | ML-KEM-512   | `2.16.840.1.101.3.4.4.1`  |
//! | ML-KEM-768   | `2.16.840.1.101.3.4.4.2`  |
//! | ML-KEM-1024  | `2.16.840.1.101.3.4.4.3`  |
//!
//! ## Status
//!
//! **Skeleton.** `publish = false`. The OID constants and the trait
//! surface are wired today so consumers and Phase 2(b) reviewers
//! can see exactly where the PKCS#8 layer will hook in. Full
//! `pkcs8::SubjectPublicKeyInfo` / `pkcs8::PrivateKeyInfo` round-trip
//! lands when the FIPS 203 spec migration (#147) is settled — until
//! then the bytes wrapped in PKCS#8 would not interop with OpenSSL
//! 3.5+ or any other FIPS 203 implementation.
//!
//! ## Design plan
//!
//! ```rust,ignore
//! use kyberlib_pkcs8::{EncapKeyEncoding, DecapKeyEncoding, MlKem768Pkcs8};
//!
//! // Public key  → SPKI DER
//! let spki = MlKem768Pkcs8::public_to_spki_der(&ek)?;
//! // Public key  → SPKI PEM (feature = "pem")
//! let pem  = MlKem768Pkcs8::public_to_spki_pem(&ek)?;
//! // Secret key → PKCS#8 DER
//! let p8   = MlKem768Pkcs8::secret_to_pkcs8_der(&dk)?;
//! ```
//!
//! Implementation hooks into RustCrypto's `pkcs8` / `spki` / `der`
//! crates. Adding those as dependencies is gated on issue #168 —
//! they pull a non-trivial transitive surface that we want vetted
//! cleanly via cargo-vet before adoption.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// IETF LAMPS object-identifier table for ML-KEM parameter sets.
///
/// These are the dotted-decimal OIDs assigned under `joint-iso-itu-t.country.us.organization.gov.csor.nistAlgorithm.kems.kyber`.
pub mod oid {
    /// ML-KEM-512 OID: `2.16.840.1.101.3.4.4.1`.
    pub const ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
    /// ML-KEM-768 OID: `2.16.840.1.101.3.4.4.2`.
    pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
    /// ML-KEM-1024 OID: `2.16.840.1.101.3.4.4.3`.
    pub const ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";
}

/// Encoding trait for the SPKI side (public keys).
///
/// The default associated constant `OID` lets each parameter-set
/// marker carry its own identifier without per-method dispatch.
pub trait EncapKeyEncoding {
    /// OID for this parameter set.
    const OID: &'static str;
}

/// Encoding trait for PKCS#8 private keys.
pub trait DecapKeyEncoding {
    /// OID for this parameter set.
    const OID: &'static str;
}

/// Marker type for ML-KEM-768 PKCS#8 / SPKI encoding.
///
/// Implementation lands with #168. Other parameter-set markers
/// (`MlKem512Pkcs8`, `MlKem1024Pkcs8`) come at the same time and
/// are gated on the Phase 3 trait redesign (#130) so all three
/// security levels are simultaneously reachable.
#[derive(Clone, Copy, Debug)]
pub struct MlKem768Pkcs8;

impl EncapKeyEncoding for MlKem768Pkcs8 {
    const OID: &'static str = oid::ML_KEM_768;
}

impl DecapKeyEncoding for MlKem768Pkcs8 {
    const OID: &'static str = oid::ML_KEM_768;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids() {
        assert_eq!(oid::ML_KEM_512, "2.16.840.1.101.3.4.4.1");
        assert_eq!(oid::ML_KEM_768, "2.16.840.1.101.3.4.4.2");
        assert_eq!(oid::ML_KEM_1024, "2.16.840.1.101.3.4.4.3");
        assert_eq!(<MlKem768Pkcs8 as EncapKeyEncoding>::OID, oid::ML_KEM_768);
        assert_eq!(<MlKem768Pkcs8 as DecapKeyEncoding>::OID, oid::ML_KEM_768);
    }
}
