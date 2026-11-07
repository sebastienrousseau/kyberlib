// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Unit tests for the typed ML-KEM API (`ml_kem.rs`), kept in their own
//! file so the module stays readable. A child module: private items are
//! still in reach through `super::*`.

use super::*;

/// **THE public-API multi-param headline test.**
///
/// Downstream consumers can now call `MlKem512::generate`,
/// `MlKem768::generate`, and `MlKem1024::generate` from the same
/// function under DEFAULT features. Each produces the correct
/// FIPS 203 §6 byte sizes, each round-trips through encap → decap
/// to a matching 32-byte shared secret.
///
/// This is the user-visible delivery of #130b: the typed `KemCore`
/// surface is fully multi-parameter-set in one build.
#[test]
fn public_api_all_three_kem_cores_in_one_build() {
    let mut rng = rand::thread_rng();

    // ML-KEM-512
    let (dk_512, ek_512) = MlKem512::generate(&mut rng).unwrap();
    let (ct_512, ss_a_512) = ek_512.encapsulate(&mut rng).unwrap();
    let ss_b_512 = dk_512.decapsulate(&ct_512);
    assert_eq!(ss_a_512, ss_b_512);

    // ML-KEM-768
    let (dk_768, ek_768) = MlKem768::generate(&mut rng).unwrap();
    let (ct_768, ss_a_768) = ek_768.encapsulate(&mut rng).unwrap();
    let ss_b_768 = dk_768.decapsulate(&ct_768);
    assert_eq!(ss_a_768, ss_b_768);

    // ML-KEM-1024
    let (dk_1024, ek_1024) = MlKem1024::generate(&mut rng).unwrap();
    let (ct_1024, ss_a_1024) = ek_1024.encapsulate(&mut rng).unwrap();
    let ss_b_1024 = dk_1024.decapsulate(&ct_1024);
    assert_eq!(ss_a_1024, ss_b_1024);

    // Byte sizes match FIPS 203 §6 Table 2.
    assert_eq!(ek_512.as_bytes().len(), 800);
    assert_eq!(ek_768.as_bytes().len(), 1184);
    assert_eq!(ek_1024.as_bytes().len(), 1568);
    assert_eq!(dk_512.as_bytes().len(), 1632);
    assert_eq!(dk_768.as_bytes().len(), 2400);
    assert_eq!(dk_1024.as_bytes().len(), 3168);
    assert_eq!(ct_512.as_bytes().len(), 768);
    assert_eq!(ct_768.as_bytes().len(), 1088);
    assert_eq!(ct_1024.as_bytes().len(), 1568);

    // Three independent secrets.
    assert_ne!(ss_a_512, ss_a_768);
    assert_ne!(ss_a_768, ss_a_1024);
    assert_ne!(ss_a_512, ss_a_1024);
}

#[test]
fn ml_kem_768_round_trip() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng).expect("keygen");
    let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
    let ss_b = dk.decapsulate(&ct);
    assert_eq!(ss_a, ss_b);
}

#[test]
fn ml_kem_512_round_trip() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem512::generate(&mut rng).expect("keygen");
    let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
    let ss_b = dk.decapsulate(&ct);
    assert_eq!(ss_a, ss_b);
}

#[test]
fn ml_kem_1024_round_trip() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem1024::generate(&mut rng).expect("keygen");
    let (ct, ss_a) = ek.encapsulate(&mut rng).expect("encap");
    let ss_b = dk.decapsulate(&ct);
    assert_eq!(ss_a, ss_b);
}

#[test]
fn ml_kem_768_oid() {
    assert_eq!(MlKem768::OID, "2.16.840.1.101.3.4.4.2");
    assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");
}

// ------- Coverage tests for the sized_wrapper_types! macro --------
//
// The MlKem512 and MlKem1024 typed wrappers exist under all feature
// combinations (the macro that generates them is unconditional);
// only KemCore impls are feature-gated. The tests below exercise
// the constructor / accessor / Debug surface across all three
// parameter sets so the macro expansion lines stay covered.

#[test]
fn ml_kem_512_encap_key_constructors() {
    let bytes = [0u8; 800];
    let ek = MlKem512EncapKey::from_bytes(bytes);
    assert_eq!(ek.as_bytes(), &bytes);
    let ek2 = MlKem512EncapKey::try_from_slice(&bytes).unwrap();
    assert_eq!(ek.as_bytes(), ek2.as_bytes());
    assert!(MlKem512EncapKey::try_from_slice(&[0u8; 100]).is_err());
    // Debug should NOT print raw bytes — "[bytes; not secret]" marker.
    #[cfg(feature = "std")]
    assert!(format!("{ek:?}").contains("not secret"));
}

#[test]
fn ml_kem_512_decap_key_constructors() {
    let bytes = [0u8; 1632];
    let dk = MlKem512DecapKey::from_bytes(bytes);
    assert_eq!(dk.as_bytes(), &bytes);
    assert!(MlKem512DecapKey::try_from_slice(&bytes).is_err());
    assert!(MlKem512DecapKey::try_from_slice(&[0u8; 100]).is_err());
    #[cfg(feature = "std")]
    assert!(format!("{dk:?}").contains("REDACTED"));
}

#[test]
fn ml_kem_512_ciphertext_constructors() {
    let bytes = [0u8; 768];
    let ct = MlKem512Ciphertext::from_bytes(bytes);
    assert_eq!(ct.as_bytes(), &bytes);
    assert!(MlKem512Ciphertext::try_from_slice(&bytes).is_ok());
    assert!(MlKem512Ciphertext::try_from_slice(&[0u8; 100]).is_err());
    #[cfg(feature = "std")]
    assert!(format!("{ct:?}").contains("opaque"));
}

#[test]
fn ml_kem_1024_encap_key_constructors() {
    let bytes = [0u8; 1568];
    let ek = MlKem1024EncapKey::from_bytes(bytes);
    assert_eq!(ek.as_bytes(), &bytes);
    assert!(MlKem1024EncapKey::try_from_slice(&bytes).is_ok());
    assert!(MlKem1024EncapKey::try_from_slice(&[0u8; 100]).is_err());
}

#[test]
fn ml_kem_1024_decap_key_constructors() {
    let bytes = [0u8; 3168];
    let dk = MlKem1024DecapKey::from_bytes(bytes);
    assert_eq!(dk.as_bytes(), &bytes);
    assert!(MlKem1024DecapKey::try_from_slice(&bytes).is_err());
    assert!(MlKem1024DecapKey::try_from_slice(&[0u8; 100]).is_err());
}

#[test]
fn ml_kem_1024_ciphertext_constructors() {
    let bytes = [0u8; 1568];
    let ct = MlKem1024Ciphertext::from_bytes(bytes);
    assert_eq!(ct.as_bytes(), &bytes);
    assert!(MlKem1024Ciphertext::try_from_slice(&bytes).is_ok());
    assert!(MlKem1024Ciphertext::try_from_slice(&[0u8; 100]).is_err());
}

#[test]
fn ml_kem_768_encap_key_try_from_slice_wrong_length() {
    assert!(MlKem768EncapKey::try_from_slice(&[0u8; 100]).is_err());
    assert!(MlKem768EncapKey::try_from_slice(&[0u8; 1184]).is_ok());
}

#[test]
fn ml_kem_768_ciphertext_try_from_slice_wrong_length() {
    assert!(MlKem768Ciphertext::try_from_slice(&[0u8; 100]).is_err());
    assert!(MlKem768Ciphertext::try_from_slice(&[0u8; 1088]).is_ok());
}

#[test]
fn shared_secret_as_bytes() {
    let ss = SharedSecret([0xAB; KYBER_SHARED_SECRET_BYTES]);
    assert_eq!(ss.as_bytes(), &[0xAB; KYBER_SHARED_SECRET_BYTES]);
    let ss2 = ss.clone();
    assert_eq!(ss, ss2);
}

#[test]
fn marker_constants_match_spec() {
    // FIPS 203 sizes, NIST IETF LAMPS OIDs.
    assert_eq!(MlKem512::K, 2);
    assert_eq!(MlKem512::PUBLIC_KEY_BYTES, 800);
    assert_eq!(MlKem512::SECRET_KEY_BYTES, 1632);
    assert_eq!(MlKem512::CIPHERTEXT_BYTES, 768);
    assert_eq!(MlKem512::ALGORITHM_ID, "ML-KEM-512");

    assert_eq!(MlKem768::K, 3);
    assert_eq!(MlKem768::PUBLIC_KEY_BYTES, 1184);
    assert_eq!(MlKem768::SECRET_KEY_BYTES, 2400);
    assert_eq!(MlKem768::CIPHERTEXT_BYTES, 1088);
    assert_eq!(MlKem768::ALGORITHM_ID, "ML-KEM-768");

    assert_eq!(MlKem1024::K, 4);
    assert_eq!(MlKem1024::PUBLIC_KEY_BYTES, 1568);
    assert_eq!(MlKem1024::SECRET_KEY_BYTES, 3168);
    assert_eq!(MlKem1024::CIPHERTEXT_BYTES, 1568);
    assert_eq!(MlKem1024::ALGORITHM_ID, "ML-KEM-1024");
}

#[test]
fn marker_types_are_zst() {
    // The marker types should be zero-sized — they exist only at
    // the type level.
    assert_eq!(size_of::<MlKem512>(), 0);
    assert_eq!(size_of::<MlKem768>(), 0);
    assert_eq!(size_of::<MlKem1024>(), 0);
}

#[test]
#[cfg(feature = "std")]
fn shared_secret_debug_is_redacted() {
    let ss = SharedSecret([0xAA; KYBER_SHARED_SECRET_BYTES]);
    assert_eq!(format!("{ss:?}"), "SharedSecret([REDACTED 32 bytes])");
}

#[test]
#[cfg(feature = "std")]
fn decap_key_debug_is_redacted() {
    let dk = MlKem768DecapKey([0xBB; KYBER_SECRET_KEY_BYTES]);
    assert_eq!(
        format!("{dk:?}"),
        "MlKem768DecapKey([REDACTED 2400 bytes])"
    );
}
