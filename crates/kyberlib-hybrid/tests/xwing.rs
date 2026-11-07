// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! X-Wing public API: round trip, seed persistence, implicit rejection.
//! The draft's known-answer vectors run as unit tests in `src/xwing.rs`.

#![cfg(feature = "xwing")]

use kyberlib_hybrid::{XWingCiphertext, XWingDecapKey, XWingEncapKey};
use rand::rngs::OsRng;

#[test]
fn round_trip_and_seed_restore() {
    let (dk, ek) = XWingDecapKey::generate(&mut OsRng).unwrap();
    let (ct, ss) = ek.encapsulate(&mut OsRng).unwrap();
    assert_eq!(dk.decapsulate(&ct), ss);

    let (restored, ek2) = XWingDecapKey::from_seed(dk.seed()).unwrap();
    assert_eq!(ek2, ek);
    assert_eq!(restored.decapsulate(&ct), ss);
}

#[test]
fn tampered_ciphertext_gives_unrelated_secret() {
    let (dk, ek) = XWingDecapKey::generate(&mut OsRng).unwrap();
    let (ct, ss) = ek.encapsulate(&mut OsRng).unwrap();
    for idx in [0usize, 1087, 1088, 1119] {
        let mut bytes = *ct.as_bytes();
        bytes[idx] ^= 1;
        let other = dk.decapsulate(&XWingCiphertext::from_bytes(bytes));
        assert_ne!(other, ss, "byte {idx}");
    }
}

#[test]
fn rejects_wrong_lengths_and_bad_mlkem_key() {
    assert!(XWingEncapKey::try_from_slice(&[0u8; 1215]).is_err());
    assert!(XWingCiphertext::try_from_slice(&[0u8; 1121]).is_err());
    let (_, ek) = XWingDecapKey::generate(&mut OsRng).unwrap();
    let mut bytes = *ek.as_bytes();
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;
    let bad = XWingEncapKey::from_bytes(bytes);
    assert_eq!(
        bad.encapsulate(&mut OsRng).err(),
        Some(kyberlib::KyberLibError::InvalidKey)
    );
}

#[test]
fn debug_output_is_redacted() {
    let (dk, ek) = XWingDecapKey::generate(&mut OsRng).unwrap();
    let (_, ss) = ek.encapsulate(&mut OsRng).unwrap();
    assert!(format!("{dk:?}").contains("REDACTED"));
    assert!(format!("{ss:?}").contains("REDACTED"));
}
