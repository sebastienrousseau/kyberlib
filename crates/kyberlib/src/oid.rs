// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Object identifiers for ML-KEM parameter sets per the IETF LAMPS
//! drafts (`draft-ietf-lamps-kyber-certificates`,
//! `draft-ietf-lamps-cms-kyber`, RFC 9936).
//!
//! These OIDs are assigned under
//! `joint-iso-itu-t.country.us.organization.gov.csor.nistAlgorithm.kems.kyber`
//! (`2.16.840.1.101.3.4.4.*`). They identify ML-KEM parameter sets in
//! X.509 SubjectPublicKeyInfo, PKCS#8 PrivateKeyInfo, and CMS
//! enveloped-data structures.
//!
//! `kyberlib-pkcs8` re-exports these from this module so the OID
//! table has a single source of truth.

/// ML-KEM-512: NIST security category 1, parameter rank `k = 2`.
/// OID `2.16.840.1.101.3.4.4.1`.
pub const ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";

/// ML-KEM-768: NIST security category 3, parameter rank `k = 3`.
/// OID `2.16.840.1.101.3.4.4.2`. The CNSA 2.0 default for TLS
/// hybrid deployments.
pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";

/// ML-KEM-1024: NIST security category 5, parameter rank `k = 4`.
/// OID `2.16.840.1.101.3.4.4.3`. Required by CNSA 2.0 for NSS by
/// 1 Jan 2027.
pub const ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_format() {
        for oid in [ML_KEM_512, ML_KEM_768, ML_KEM_1024] {
            // Sanity-check: dotted-decimal, ASCII digits and dots only.
            assert!(oid
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.'));
            assert!(oid.starts_with("2.16.840.1.101.3.4.4."));
        }
    }
}
