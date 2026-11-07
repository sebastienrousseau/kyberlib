// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Password-encrypted PKCS#8 (PBES2): interop with OpenSSL 3.5, round
//! trips, and the cost limits that keep a hostile file from running an
//! unbounded key-derivation function.

use kyberlib::{MlKem1024, MlKem512, MlKem768};
use kyberlib_pkcs8::der::{Decode, Document, Encode};
use kyberlib_pkcs8::pkcs8::pkcs5::{self, pbes2};
use kyberlib_pkcs8::pkcs8::{EncryptedPrivateKeyInfoRef, Error};
use kyberlib_pkcs8::{
    DecodePrivateKey, DecryptLimits, LineEnding, Params, PrivateKey,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const PASSWORD: &str = "kyberlib-test-password";

fn vector(set: &str, file: &str) -> String {
    let path: PathBuf =
        [env!("CARGO_MANIFEST_DIR"), "tests/vectors", set, file]
            .iter()
            .collect();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn openssl_files<P: Params>(set: &str)
where
    P::DecapsulationKey: PartialEq + core::fmt::Debug,
{
    let plain =
        PrivateKey::<P>::from_pkcs8_pem(&vector(set, "private.pem"))
            .unwrap();
    for file in ["encrypted-pbkdf2.pem", "encrypted-scrypt.pem"] {
        let pem = vector(set, file);
        let key = PrivateKey::<P>::decrypt_pkcs8_pem(&pem, PASSWORD)
            .unwrap_or_else(|e| panic!("{set}/{file}: {e}"));
        assert_eq!(
            key.decapsulation_key(),
            plain.decapsulation_key(),
            "{set}/{file}"
        );
        assert!(
            PrivateKey::<P>::decrypt_pkcs8_pem(&pem, "wrong password")
                .is_err(),
            "{set}/{file}"
        );
    }
}

#[test]
fn decrypts_openssl_files() {
    openssl_files::<MlKem512>("ml-kem-512");
    openssl_files::<MlKem768>("ml-kem-768");
    openssl_files::<MlKem1024>("ml-kem-1024");
}

#[test]
fn round_trips_der_and_pem() {
    let key = PrivateKey::<MlKem768>::generate(&mut rand::rngs::OsRng)
        .unwrap();

    let pem = key
        .encrypt_to_pkcs8_pem(
            &mut rand::rngs::OsRng,
            PASSWORD,
            LineEnding::LF,
        )
        .unwrap();
    assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let back =
        PrivateKey::<MlKem768>::decrypt_pkcs8_pem(&pem, PASSWORD)
            .unwrap();
    assert_eq!(back.decapsulation_key(), key.decapsulation_key());
    assert_eq!(back.seed(), key.seed());

    let der = key
        .encrypt_to_pkcs8_der(&mut rand::rngs::OsRng, PASSWORD)
        .unwrap();
    let back = PrivateKey::<MlKem768>::decrypt_pkcs8_der(
        der.as_bytes(),
        PASSWORD,
    )
    .unwrap();
    assert_eq!(back.decapsulation_key(), key.decapsulation_key());
    assert!(PrivateKey::<MlKem768>::decrypt_pkcs8_der(
        der.as_bytes(),
        "nope"
    )
    .is_err());
}

#[test]
fn refuses_pbkdf2_with_sha1() {
    let pem = vector("ml-kem-768", "encrypted-pbkdf2-sha1.pem");
    assert!(PrivateKey::<MlKem768>::decrypt_pkcs8_pem(&pem, PASSWORD)
        .is_err());
}

#[test]
fn rejects_an_unencrypted_document() {
    let pem = vector("ml-kem-768", "private.pem");
    assert!(PrivateKey::<MlKem768>::decrypt_pkcs8_pem(&pem, PASSWORD)
        .is_err());
}

/// Re-encodes an OpenSSL file with different PBES2 parameters. The
/// ciphertext no longer matches, but the limits must reject the file
/// before the KDF runs, so the error says "parameters", not "decrypt".
fn with_params(
    set: &str,
    file: &str,
    edit: impl FnOnce(&mut pbes2::Parameters),
) -> Vec<u8> {
    let (_, doc) = Document::from_pem(&vector(set, file)).unwrap();
    let mut info =
        EncryptedPrivateKeyInfoRef::from_der(doc.as_bytes()).unwrap();
    let pkcs5::EncryptionScheme::Pbes2(params) =
        &mut info.encryption_algorithm
    else {
        panic!("not PBES2");
    };
    edit(params);
    info.to_der().unwrap()
}

fn assert_refused_fast(
    der: &[u8],
    limits: &DecryptLimits,
    kdf_oid: pkcs5::ObjectIdentifier,
) {
    let start = Instant::now();
    let err = PrivateKey::<MlKem768>::decrypt_pkcs8_der_with_limits(
        der, PASSWORD, limits,
    )
    .unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "KDF ran: {:?}",
        start.elapsed()
    );
    assert_eq!(
        err,
        Error::EncryptedPrivateKey(
            pkcs5::Error::AlgorithmParametersInvalid { oid: kdf_oid }
        )
    );
}

#[test]
fn pbkdf2_iterations_are_capped() {
    let file = vector("ml-kem-768", "encrypted-pbkdf2.pem");
    let (_, doc) = Document::from_pem(&file).unwrap();
    // OpenSSL's file uses 2048 iterations: a cap of 1000 refuses it.
    let tight =
        DecryptLimits::default().with_max_pbkdf2_iterations(1000);
    assert_refused_fast(doc.as_bytes(), &tight, pbes2::PBKDF2_OID);

    let huge = with_params("ml-kem-768", "encrypted-pbkdf2.pem", |p| {
        if let pbes2::Kdf::Pbkdf2(k) = &mut p.kdf {
            k.iteration_count = u32::MAX;
        }
    });
    assert_refused_fast(
        &huge,
        &DecryptLimits::default(),
        pbes2::PBKDF2_OID,
    );
}

#[test]
fn scrypt_memory_and_parallelism_are_capped() {
    let file = vector("ml-kem-768", "encrypted-scrypt.pem");
    let (_, doc) = Document::from_pem(&file).unwrap();
    // OpenSSL's file needs 128 * r * N = 16 MiB: an 8 MiB cap refuses it.
    let tight =
        DecryptLimits::default().with_max_scrypt_memory(8 << 20);
    assert_refused_fast(doc.as_bytes(), &tight, pbes2::SCRYPT_OID);

    let big_n =
        with_params("ml-kem-768", "encrypted-scrypt.pem", |p| {
            if let pbes2::Kdf::Scrypt(k) = &mut p.kdf {
                k.cost_parameter = 1 << 30; // 128 GiB with r = 8
            }
        });
    assert_refused_fast(
        &big_n,
        &DecryptLimits::default(),
        pbes2::SCRYPT_OID,
    );

    let big_p =
        with_params("ml-kem-768", "encrypted-scrypt.pem", |p| {
            if let pbes2::Kdf::Scrypt(k) = &mut p.kdf {
                k.parallelization = u16::MAX;
            }
        });
    assert_refused_fast(
        &big_p,
        &DecryptLimits::default(),
        pbes2::SCRYPT_OID,
    );
}

#[test]
fn default_limits_accept_what_this_crate_and_openssl_write() {
    let limits = DecryptLimits::default();
    assert!(
        limits.max_pbkdf2_iterations >= 600_000,
        "OWASP PBKDF2-SHA256 guidance"
    );
    assert!(
        limits.max_scrypt_memory >= 32 << 20,
        "OpenSSL's scrypt default ceiling"
    );
}
