// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `KemCore::generate_from_seed` is FIPS 203 `ML-KEM.KeyGen_internal`:
//! it must match the seeded generic pipeline that the NIST ACVP keyGen
//! vectors exercise, for every parameter set, and be deterministic.

use kyberlib::__testing__::kem_keypair_generic;
use kyberlib::{KemCore, MlKem1024, MlKem512, MlKem768};
use rand::rngs::OsRng;

fn check<
    P: KemCore + kyberlib::MlKemParams,
    const PK: usize,
    const SK: usize,
>(
    ek_of: impl Fn(&P::EncapsulationKey) -> [u8; PK],
    dk_of: impl Fn(&P::DecapsulationKey) -> [u8; SK],
) {
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let (dk, ek) = P::generate_from_seed(&d, &z).unwrap();
    let mut pk = [0u8; PK];
    let mut sk = [0u8; SK];
    kem_keypair_generic::<P, _>(
        &mut pk,
        &mut sk,
        &mut OsRng,
        Some((&d, &z)),
    )
    .unwrap();
    assert_eq!(ek_of(&ek), pk, "{}: ek", <P as KemCore>::ALGORITHM_ID);
    assert_eq!(dk_of(&dk), sk, "{}: dk", <P as KemCore>::ALGORITHM_ID);

    let (dk2, ek2) = P::generate_from_seed(&d, &z).unwrap();
    assert_eq!(
        ek_of(&ek2),
        pk,
        "{}: deterministic",
        <P as KemCore>::ALGORITHM_ID
    );
    assert_eq!(dk_of(&dk2), sk);
    let (_, other) = P::generate_from_seed(&z, &d).unwrap();
    assert_ne!(
        ek_of(&other),
        pk,
        "{}: seed matters",
        <P as KemCore>::ALGORITHM_ID
    );
}

#[test]
fn seeded_keygen_matches_generic_pipeline() {
    check::<MlKem512, 800, 1632>(|e| *e.as_bytes(), |d| *d.as_bytes());
    check::<MlKem768, 1184, 2400>(|e| *e.as_bytes(), |d| *d.as_bytes());
    check::<MlKem1024, 1568, 3168>(
        |e| *e.as_bytes(),
        |d| *d.as_bytes(),
    );
}
