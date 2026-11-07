// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Inputs RFC 9935 or FIPS 203 say must be rejected.

use kyberlib::{MlKem512, MlKem768};
use kyberlib_pkcs8::der::asn1::{AnyRef, BitStringRef, OctetStringRef};
use kyberlib_pkcs8::der::Encode;
use kyberlib_pkcs8::pkcs8::PrivateKeyInfoRef;
use kyberlib_pkcs8::spki::{
    AlgorithmIdentifierRef, SubjectPublicKeyInfoRef,
};
use kyberlib_pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey,
    EncodePublicKey, Params, PrivateKey, PrivateKeyFormat, PublicKey,
};

const SEED: [u8; 64] = [0x42; 64];

fn key() -> PrivateKey<MlKem768> {
    PrivateKey::from_seed(&SEED).unwrap()
}

/// A PKCS#8 document for ML-KEM-768 around an arbitrary inner CHOICE.
fn pkcs8(
    inner: &[u8],
    params: Option<AnyRef<'_>>,
    public: Option<&[u8]>,
) -> Vec<u8> {
    let mut info = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid: MlKem768::OBJECT_ID,
            parameters: params,
        },
        OctetStringRef::new(inner).unwrap(),
    );
    info.public_key =
        public.map(|p| BitStringRef::from_bytes(p).unwrap());
    info.to_der().unwrap()
}

fn inner(format: PrivateKeyFormat) -> Vec<u8> {
    let der =
        key().with_format(format).unwrap().to_pkcs8_der().unwrap();
    let info = PrivateKeyInfoRef::try_from(der.as_bytes()).unwrap();
    info.private_key.as_bytes().to_vec()
}

#[test]
fn round_trips_every_form() {
    for format in [
        PrivateKeyFormat::Seed,
        PrivateKeyFormat::Expanded,
        PrivateKeyFormat::Both,
    ] {
        let der = pkcs8(&inner(format), None, None);
        let back =
            PrivateKey::<MlKem768>::from_pkcs8_der(&der).unwrap();
        assert_eq!(back.format(), format);
        assert_eq!(back.decapsulation_key(), key().decapsulation_key());
        assert_eq!(
            back.seed().is_some(),
            format != PrivateKeyFormat::Expanded
        );
    }
}

#[test]
fn both_form_with_inconsistent_seed_is_rejected() {
    let mut both = inner(PrivateKeyFormat::Both);
    let last = both.len() - 1; // inside expandedKey's z
    both[last] ^= 1;
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &both, None, None
    ))
    .is_err());
    let mut both = inner(PrivateKeyFormat::Both);
    both[4] ^= 1; // first seed byte
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &both, None, None
    ))
    .is_err());
}

#[test]
fn expanded_form_runs_the_hash_check() {
    let mut expanded = inner(PrivateKeyFormat::Expanded);
    let h = expanded.len() - 64; // H(ek), before the 32-byte z
    expanded[h] ^= 1;
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &expanded, None, None
    ))
    .is_err());
}

#[test]
fn parameters_must_be_absent() {
    let der =
        pkcs8(&inner(PrivateKeyFormat::Seed), Some(AnyRef::NULL), None);
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&der).is_err());

    let ek = key().public_key().to_public_key_der().unwrap();
    let spki =
        SubjectPublicKeyInfoRef::try_from(ek.as_bytes()).unwrap();
    let with_params = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            parameters: Some(AnyRef::NULL),
            ..spki.algorithm
        },
        ..spki
    };
    let der = with_params.to_der().unwrap();
    assert!(PublicKey::<MlKem768>::from_public_key_der(&der).is_err());
}

#[test]
fn oid_must_match_the_parameter_set() {
    let der = key().to_pkcs8_der().unwrap();
    assert!(
        PrivateKey::<MlKem512>::from_pkcs8_der(der.as_bytes()).is_err()
    );
    let der = key().public_key().to_public_key_der().unwrap();
    assert!(PublicKey::<MlKem512>::from_public_key_der(der.as_bytes())
        .is_err());
}

#[test]
fn public_key_field_must_match() {
    let ek = key().public_key().into_key();
    let seed = inner(PrivateKeyFormat::Seed);
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &seed,
        None,
        Some(ek.as_bytes())
    ))
    .is_ok());
    let mut other = *ek.as_bytes();
    other[0] ^= 1;
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &seed,
        None,
        Some(&other)
    ))
    .is_err());
}

#[test]
fn pre_standard_bare_forms_are_rejected() {
    // Early drafts put the raw seed or key directly in privateKey.
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &SEED, None, None
    ))
    .is_err());
    let dk = key().decapsulation_key().as_bytes().to_vec();
    assert!(PrivateKey::<MlKem768>::from_pkcs8_der(&pkcs8(
        &dk, None, None
    ))
    .is_err());
}

#[test]
fn public_key_runs_the_modulus_check_and_rejects_unused_bits() {
    let ek = key().public_key().into_key();
    let mut bad = *ek.as_bytes();
    bad[0] = 0xFF;
    bad[1] |= 0x0F; // first coefficient = 4095 >= q
    let alg = AlgorithmIdentifierRef {
        oid: MlKem768::OBJECT_ID,
        parameters: None,
    };
    let der = SubjectPublicKeyInfoRef {
        algorithm: alg,
        subject_public_key: BitStringRef::from_bytes(&bad).unwrap(),
    }
    .to_der()
    .unwrap();
    assert!(PublicKey::<MlKem768>::from_public_key_der(&der).is_err());

    let der = SubjectPublicKeyInfoRef {
        algorithm: alg,
        subject_public_key: BitStringRef::new(1, ek.as_bytes())
            .unwrap(),
    }
    .to_der()
    .unwrap();
    assert!(PublicKey::<MlKem768>::from_public_key_der(&der).is_err());
}

#[test]
fn seed_forms_need_a_seed() {
    let dk = key().decapsulation_key().clone();
    let expanded = PrivateKey::<MlKem768>::from_expanded(dk).unwrap();
    assert!(expanded.seed().is_none());
    assert!(PrivateKey::<MlKem768>::from_expanded(
        key().decapsulation_key().clone()
    )
    .unwrap()
    .with_format(PrivateKeyFormat::Seed)
    .is_err());
    assert!(expanded.with_format(PrivateKeyFormat::Both).is_err());
}

#[test]
fn debug_does_not_print_secrets() {
    let text = format!("{:?}", key());
    assert!(text.contains("REDACTED"));
    assert!(!text.contains("66")); // 0x42 in decimal
}
