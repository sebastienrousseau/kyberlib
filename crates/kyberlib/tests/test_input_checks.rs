// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS 203 §7.2 and §7.3 input checks.
//!
//! §7.2: before encapsulating, an encapsulation key's 12-bit
//! coefficients must all be below q = 3329 (the modulus check).
//! §7.3: a decapsulation key imported from bytes must carry the hash
//! H(ek) of its own embedded encapsulation key (the hash check).

use kyberlib::{
    KemCore, KyberLibError, MlKem1024, MlKem1024DecapKey,
    MlKem1024EncapKey, MlKem512, MlKem512DecapKey, MlKem512EncapKey,
    MlKem768, MlKem768EncapKey,
};
use rand::rngs::OsRng;

/// Sets the first coefficient of the encoded polynomial vector to
/// 0xFFF = 4095, which is >= q and so fails the modulus check.
fn poison(ek: &mut [u8]) {
    ek[0] = 0xFF;
    ek[1] |= 0x0F;
}

#[test]
fn encapsulate_rejects_unreduced_coefficients_768() {
    let (_, ek) = MlKem768::generate(&mut OsRng).unwrap();
    let mut bytes = *ek.as_bytes();
    poison(&mut bytes);
    let bad = MlKem768EncapKey::from_bytes(bytes);
    assert_eq!(
        bad.encapsulate(&mut OsRng).err(),
        Some(KyberLibError::InvalidKey)
    );
    assert!(
        ek.encapsulate(&mut OsRng).is_ok(),
        "valid key still works"
    );
}

#[test]
fn encapsulate_rejects_unreduced_coefficients_512_and_1024() {
    let (_, ek) = MlKem512::generate(&mut OsRng).unwrap();
    let mut b512 = *ek.as_bytes();
    poison(&mut b512);
    assert_eq!(
        MlKem512EncapKey::from_bytes(b512)
            .encapsulate(&mut OsRng)
            .err(),
        Some(KyberLibError::InvalidKey)
    );
    let (_, ek) = MlKem1024::generate(&mut OsRng).unwrap();
    let mut b1024 = *ek.as_bytes();
    poison(&mut b1024);
    assert_eq!(
        MlKem1024EncapKey::from_bytes(b1024)
            .encapsulate(&mut OsRng)
            .err(),
        Some(KyberLibError::InvalidKey)
    );
}

#[test]
fn legacy_encapsulate_rejects_unreduced_coefficients() {
    let kp = kyberlib::keypair(&mut OsRng).unwrap();
    let mut bad = kp.public;
    poison(&mut bad);
    assert_eq!(
        kyberlib::encapsulate(&bad, &mut OsRng).err(),
        Some(KyberLibError::InvalidKey)
    );
}

#[test]
fn decap_key_import_checks_embedded_hash() {
    let (dk, _) = MlKem512::generate(&mut OsRng).unwrap();
    let good = dk.as_bytes().to_vec();
    assert!(MlKem512DecapKey::try_from_slice(&good).is_ok());
    let mut bad = good;
    let h = bad.len() - 64; // H(ek) sits just before the 32-byte z
    bad[h] ^= 1;
    assert_eq!(
        MlKem512DecapKey::try_from_slice(&bad).err(),
        Some(KyberLibError::InvalidKey)
    );

    let (dk, _) = MlKem1024::generate(&mut OsRng).unwrap();
    let mut bad = dk.as_bytes().to_vec();
    let h = bad.len() - 64;
    bad[h] ^= 1;
    assert_eq!(
        MlKem1024DecapKey::try_from_slice(&bad).err(),
        Some(KyberLibError::InvalidKey)
    );
}

#[test]
fn encap_key_validate_runs_the_modulus_check() {
    let (_, ek) = MlKem512::generate(&mut OsRng).unwrap();
    assert_eq!(ek.validate(), Ok(()));
    let mut b = *ek.as_bytes();
    poison(&mut b);
    assert_eq!(
        MlKem512EncapKey::from_bytes(b).validate(),
        Err(KyberLibError::InvalidKey)
    );

    let (_, ek) = MlKem768::generate(&mut OsRng).unwrap();
    assert_eq!(ek.validate(), Ok(()));
    let mut b = *ek.as_bytes();
    poison(&mut b);
    assert_eq!(
        MlKem768EncapKey::from_bytes(b).validate(),
        Err(KyberLibError::InvalidKey)
    );

    let (_, ek) = MlKem1024::generate(&mut OsRng).unwrap();
    assert_eq!(ek.validate(), Ok(()));
    // The last coefficient sits just before the 32-byte rho suffix.
    let mut b = *ek.as_bytes();
    let end = b.len() - 32;
    b[end - 1] = 0xFF;
    b[end - 2] |= 0xF0;
    assert_eq!(
        MlKem1024EncapKey::from_bytes(b).validate(),
        Err(KyberLibError::InvalidKey)
    );
}

#[test]
fn decap_key_import_768_checks_length_and_hash() {
    let (dk, ek) = MlKem768::generate(&mut OsRng).unwrap();
    let good = dk.as_bytes().to_vec();
    let imported =
        kyberlib::MlKem768DecapKey::try_from_slice(&good).unwrap();
    assert_eq!(imported, dk);
    let (ct, ss) = ek.encapsulate(&mut OsRng).unwrap();
    assert_eq!(imported.decapsulate(&ct), ss);

    assert_eq!(
        kyberlib::MlKem768DecapKey::try_from_slice(&good[1..]).err(),
        Some(KyberLibError::InvalidLength)
    );
    let mut bad = good;
    let h = bad.len() - 64;
    bad[h] ^= 1;
    assert_eq!(
        kyberlib::MlKem768DecapKey::try_from_slice(&bad).err(),
        Some(KyberLibError::InvalidKey)
    );
}
