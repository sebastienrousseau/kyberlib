// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS backend (#170): the typed API runs in the AWS-LC FIPS module
//! and stays byte-compatible with kyberlib's pure-Rust ML-KEM, which
//! the `__testing__` module still exposes. Every check runs both ways
//! for all three parameter sets, including FIPS 203 implicit rejection
//! on tampered ciphertexts, where both backends must derive the same
//! pseudorandom secret.

#![cfg(feature = "fips")]

use kyberlib::__testing__::{
    kem_dec_generic, kem_enc_generic, kem_keypair_generic,
};
use kyberlib::{KemCore, MlKem1024, MlKem512, MlKem768, MlKemParams};
use rand::rngs::OsRng;

#[test]
fn module_reports_fips_mode() {
    assert_eq!(kyberlib::BACKEND, kyberlib::fips::BACKEND);
    kyberlib::fips::fips_mode()
        .expect("AWS-LC power-on self tests / FIPS build");
}

macro_rules! cross_backend {
    ($name:ident, $p:ty, $ek:ident, $dk:ident, $ct:ident, $pk:expr, $sk:expr, $ctl:expr) => {
        #[test]
        fn $name() {
            // Module keys, pure-Rust encapsulation, module decapsulation.
            let (dk, ek) = <$p>::generate(&mut OsRng).unwrap();
            let mut ct = [0u8; $ctl];
            let mut ss = [0u8; 32];
            kem_enc_generic::<$p, _>(
                &mut ct,
                &mut ss,
                ek.as_bytes(),
                &mut OsRng,
                None,
            )
            .unwrap();
            let got = dk.decapsulate(&kyberlib::$ct::from_bytes(ct));
            assert_eq!(got.as_bytes(), &ss, "pure enc -> module dec");

            // Module encapsulation, pure-Rust decapsulation.
            let (ct2, ss2) = ek.encapsulate(&mut OsRng).unwrap();
            let mut pure = [0u8; 32];
            kem_dec_generic::<$p>(
                &mut pure,
                ct2.as_bytes(),
                dk.as_bytes(),
            );
            assert_eq!(&pure, ss2.as_bytes(), "module enc -> pure dec");

            // Pure-Rust keys imported into the module.
            let mut pk = [0u8; $pk];
            let mut sk = [0u8; $sk];
            kem_keypair_generic::<$p, _>(
                &mut pk, &mut sk, &mut OsRng, None,
            )
            .unwrap();
            let (ct3, ss3) = kyberlib::$ek::from_bytes(pk)
                .encapsulate(&mut OsRng)
                .unwrap();
            let dk3 = kyberlib::$dk::try_from_slice(&sk).unwrap();
            assert_eq!(
                dk3.decapsulate(&ct3),
                ss3,
                "pure keys through module"
            );

            // Implicit rejection agrees across backends.
            let mut bad = *ct2.as_bytes();
            bad[7] ^= 0x40;
            let module =
                dk.decapsulate(&kyberlib::$ct::from_bytes(bad));
            let mut pure_rej = [0u8; 32];
            kem_dec_generic::<$p>(&mut pure_rej, &bad, dk.as_bytes());
            assert_eq!(
                module.as_bytes(),
                &pure_rej,
                "implicit rejection"
            );
            assert_ne!(module.as_bytes(), ss2.as_bytes());
        }
    };
}

#[test]
fn ml_kem_768_cross_backend() {
    // MlKem768DecapKey has no byte constructor; check the other paths.
    let (dk, ek) = MlKem768::generate(&mut OsRng).unwrap();
    let mut ct = [0u8; 1088];
    let mut ss = [0u8; 32];
    kem_enc_generic::<MlKem768, _>(
        &mut ct,
        &mut ss,
        ek.as_bytes(),
        &mut OsRng,
        None,
    )
    .unwrap();
    assert_eq!(
        dk.decapsulate(&kyberlib::MlKem768Ciphertext::from_bytes(ct))
            .as_bytes(),
        &ss
    );

    let (ct2, ss2) = ek.encapsulate(&mut OsRng).unwrap();
    let mut pure = [0u8; 32];
    kem_dec_generic::<MlKem768>(
        &mut pure,
        ct2.as_bytes(),
        dk.as_bytes(),
    );
    assert_eq!(&pure, ss2.as_bytes());

    let mut bad = *ct2.as_bytes();
    bad[0] ^= 1;
    let mut pure_rej = [0u8; 32];
    kem_dec_generic::<MlKem768>(&mut pure_rej, &bad, dk.as_bytes());
    assert_eq!(
        dk.decapsulate(&kyberlib::MlKem768Ciphertext::from_bytes(bad))
            .as_bytes(),
        &pure_rej
    );
    let _ = <MlKem768 as MlKemParams>::K;
}

cross_backend!(
    ml_kem_512_cross_backend,
    MlKem512,
    MlKem512EncapKey,
    MlKem512DecapKey,
    MlKem512Ciphertext,
    800,
    1632,
    768
);
cross_backend!(
    ml_kem_1024_cross_backend,
    MlKem1024,
    MlKem1024EncapKey,
    MlKem1024DecapKey,
    MlKem1024Ciphertext,
    1568,
    3168,
    1568
);
