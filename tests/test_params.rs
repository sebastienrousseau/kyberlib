// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    // Import necessary items
    use kyberlib::params::*;

    // Test Kyber parameters related to features

    #[test]
    fn test_kyber_90s() {
        // Test if KYBER_90S matches the feature configuration
        assert_eq!(KYBER_90S, cfg!(feature = "90s"));
    }

    #[test]
    fn test_kyber_eta1() {
        // Test KYBER_ETA1 depending on feature configuration
        if cfg!(feature = "kyber512") {
            assert_eq!(KYBER_ETA1, 3);
        } else {
            assert_eq!(KYBER_ETA1, 2);
        }
    }

    #[test]
    fn test_kyber_eta2() {
        // Test KYBER_ETA2
        assert_eq!(KYBER_ETA2, 2);
    }

    #[test]
    fn test_kyber_n() {
        // Test KYBER_N
        assert_eq!(KYBER_N, 256);
    }

    #[test]
    fn test_kyber_poly_bytes() {
        // Test KYBER_POLY_BYTES
        assert_eq!(KYBER_POLY_BYTES, 384);
    }

    #[cfg(not(feature = "kyber1024"))]
    #[test]
    fn test_kyber_poly_compressed_bytes() {
        // Test KYBER_POLY_COMPRESSED_BYTES for non-kyber1024
        assert_eq!(KYBER_POLY_COMPRESSED_BYTES, 128);
    }

    #[test]
    fn test_kyber_polyvec_bytes() {
        // Test KYBER_POLYVEC_BYTES
        assert_eq!(
            KYBER_POLYVEC_BYTES,
            KYBER_SECURITY_PARAMETER * KYBER_POLY_BYTES
        );
    }

    #[cfg(not(feature = "kyber1024"))]
    #[test]
    fn test_kyber_polyvec_compressed_bytes() {
        // Test KYBER_POLYVEC_COMPRESSED_BYTES for non-kyber1024
        assert_eq!(
            KYBER_POLYVEC_COMPRESSED_BYTES,
            KYBER_SECURITY_PARAMETER * 320
        );
    }

    #[test]
    fn test_kyber_q() {
        // Test KYBER_Q
        assert_eq!(KYBER_Q, 3329);
    }

    // Test Kyber parameters related to sizes

    #[test]
    fn test_kyber_secret_key_bytes() {
        // Test KYBER_SECRET_KEY_BYTES
        assert_eq!(
            KYBER_SECRET_KEY_BYTES,
            KYBER_INDCPA_SECRET_KEY_BYTES
                + KYBER_INDCPA_PUBLIC_KEY_BYTES
                + 2 * KYBER_SYM_BYTES
        );
    }

    #[test]
    fn test_kyber_security_parameter() {
        // Test KYBER_SECURITY_PARAMETER
        if cfg!(feature = "kyber512") {
            assert_eq!(KYBER_SECURITY_PARAMETER, 2);
        } else if cfg!(feature = "kyber1024") {
            assert_eq!(KYBER_SECURITY_PARAMETER, 4);
        } else {
            assert_eq!(KYBER_SECURITY_PARAMETER, 3);
        }
    }

    #[test]
    fn test_kyber_shared_secret_bytes() {
        // Test KYBER_SHARED_SECRET_BYTES
        assert_eq!(KYBER_SHARED_SECRET_BYTES, 32);
    }

    #[test]
    fn test_kyber_sym_bytes() {
        // Test KYBER_SYM_BYTES
        assert_eq!(KYBER_SYM_BYTES, 32);
    }

    // Test Kyber parameters related to kyber1024 feature

    #[cfg(feature = "kyber1024")]
    #[test]
    fn test_KYBER_POLY_COMPRESSED_BYTES_kyber1024() {
        // Test KYBER_POLY_COMPRESSED_BYTES for kyber1024
        assert_eq!(KYBER_POLY_COMPRESSED_BYTES, 160);
    }

    #[cfg(feature = "kyber1024")]
    #[test]
    fn test_KYBER_POLYVEC_COMPRESSED_BYTES_kyber1024() {
        // Test KYBER_POLYVEC_COMPRESSED_BYTES for kyber1024
        assert_eq!(
            KYBER_POLYVEC_COMPRESSED_BYTES,
            KYBER_SECURITY_PARAMETER * 352
        );
    }

    // Test Kyber parameters related to indcpa

    #[test]
    fn test_kyber_indcpa_public_key_bytes() {
        // Test KYBER_INDCPA_PUBLIC_KEY_BYTES
        assert_eq!(
            KYBER_INDCPA_PUBLIC_KEY_BYTES,
            KYBER_POLYVEC_BYTES + KYBER_SYM_BYTES
        );
    }

    #[test]
    fn test_kyber_indcpa_secret_key_bytes() {
        // Test KYBER_INDCPA_SECRET_KEY_BYTES
        assert_eq!(KYBER_INDCPA_SECRET_KEY_BYTES, KYBER_POLYVEC_BYTES);
    }

    #[test]
    fn test_kyber_indcpa_bytes() {
        // Test KYBER_INDCPA_BYTES
        assert_eq!(
            KYBER_INDCPA_BYTES,
            KYBER_POLYVEC_COMPRESSED_BYTES
                + KYBER_POLY_COMPRESSED_BYTES
        );
    }

    // Test Kyber parameters related to keys and ciphertext

    #[test]
    fn test_kyber_public_key_bytes() {
        // Test KYBER_PUBLIC_KEY_BYTES
        assert_eq!(
            KYBER_PUBLIC_KEY_BYTES,
            KYBER_INDCPA_PUBLIC_KEY_BYTES
        );
    }

    #[test]
    fn test_kyber_ciphertext_bytes() {
        // Test KYBER_CIPHERTEXT_BYTES
        assert_eq!(KYBER_CIPHERTEXT_BYTES, KYBER_INDCPA_BYTES);
    }
}
