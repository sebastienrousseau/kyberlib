// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interop with OpenSSL 3.5 (`tests/vectors`, made by `regen.sh` from
//! fixed seeds). For each parameter set, every form OpenSSL writes must
//! decode to the same key, re-encode byte for byte, and agree with the
//! key kyberlib derives from the same seed.

use kyberlib::{MlKem1024, MlKem512, MlKem768};
use kyberlib_pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey,
    EncodePublicKey, LineEnding, Params, PrivateKey, PrivateKeyFormat,
    PublicKey,
};
use std::path::PathBuf;

fn vector(set: &str, file: &str) -> Vec<u8> {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "tests/vectors", set, file]
            .iter()
            .collect();
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn pem(set: &str, file: &str) -> String {
    String::from_utf8(vector(set, file)).unwrap()
}

/// The seed `regen.sh` used: byte i = (i + n mod 251) mod 256.
fn seed(n: usize) -> [u8; 64] {
    core::array::from_fn(|i| ((i + n % 251) % 256) as u8)
}

fn check<P: Params>(set: &str, n: usize)
where
    P::DecapsulationKey: PartialEq + core::fmt::Debug + Clone,
    P::EncapsulationKey: PartialEq + core::fmt::Debug + Clone,
{
    let ours = PrivateKey::<P>::from_seed(&seed(n)).unwrap();
    let forms = [
        ("seed-only.der", PrivateKeyFormat::Seed),
        ("priv-only.der", PrivateKeyFormat::Expanded),
        ("seed-priv.der", PrivateKeyFormat::Both),
    ];
    for (file, format) in forms {
        let der = vector(set, file);
        let key = PrivateKey::<P>::from_pkcs8_der(&der).unwrap();
        assert_eq!(key.format(), format, "{set}/{file}");
        assert_eq!(
            key.decapsulation_key(),
            ours.decapsulation_key(),
            "{set}/{file}"
        );
        assert_eq!(
            key.encapsulation_key(),
            ours.encapsulation_key(),
            "{set}/{file}"
        );
        assert_eq!(
            key.to_pkcs8_der().unwrap().as_bytes(),
            der.as_slice(),
            "{set}/{file}"
        );
        // A key built by us in the same form encodes to OpenSSL's bytes.
        let mine = PrivateKey::<P>::from_seed(&seed(n)).unwrap();
        let mine = if format == PrivateKeyFormat::Expanded {
            PrivateKey::<P>::from_expanded(
                mine.decapsulation_key().clone(),
            )
            .unwrap()
        } else {
            mine.with_format(format).unwrap()
        };
        assert_eq!(
            mine.to_pkcs8_der().unwrap().as_bytes(),
            der.as_slice(),
            "{set}/{file}"
        );
    }

    check_public_and_pem::<P>(set, &ours);
}

fn check_public_and_pem<P: Params>(set: &str, ours: &PrivateKey<P>)
where
    P::EncapsulationKey: PartialEq + core::fmt::Debug + Clone,
{
    let spki = vector(set, "spki.der");
    let public = PublicKey::<P>::from_public_key_der(&spki).unwrap();
    assert_eq!(public.key(), ours.encapsulation_key());
    assert_eq!(
        ours.public_key().to_public_key_der().unwrap().as_bytes(),
        spki.as_slice()
    );

    // PEM: OpenSSL's default private form is `both`.
    let private_pem = pem(set, "private.pem");
    let key = PrivateKey::<P>::from_pkcs8_pem(&private_pem).unwrap();
    assert_eq!(key.format(), PrivateKeyFormat::Both);
    assert_eq!(
        key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
        private_pem
    );
    let public_pem = pem(set, "public.pem");
    assert_eq!(
        public.to_public_key_pem(LineEnding::LF).unwrap(),
        public_pem
    );
}

#[test]
fn openssl_ml_kem_512() {
    check::<MlKem512>("ml-kem-512", 512);
}

#[test]
fn openssl_ml_kem_768() {
    check::<MlKem768>("ml-kem-768", 768);
}

#[test]
fn openssl_ml_kem_1024() {
    check::<MlKem1024>("ml-kem-1024", 1024);
}
