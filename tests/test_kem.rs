use kyberlib::*;
mod utils;
use kyberlib::keypairfrom;
use utils::FailingRng;

#[test]
fn keypair_encap_decap() {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let (ct, ss1) = encapsulate(&keys.public, &mut rng).unwrap();
    let ss2 = decapsulate(&ct, &keys.secret).unwrap();
    assert_eq!(ss1, ss2);
}

#[test]
fn keypair_import_fake() {
    let mut rng = rand::thread_rng();
    let mut keys = keypair(&mut rng).unwrap();
    let key = keypairfrom(&mut keys.public, &mut keys.secret, &mut rng)
        .unwrap();
    assert_eq!(keys.public, key.public);
}

#[test]
fn keypair_encap_decap_invalid_ciphertext() {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let (mut ct, ss) = encapsulate(&keys.public, &mut rng).unwrap();
    ct[..4].copy_from_slice(&[255u8; 4]);
    assert!(decapsulate(&ct, &keys.secret).unwrap() != ss);
}

#[test]
fn keypair_encap_pk_wrong_size() {
    let mut rng = rand::thread_rng();
    let pk: [u8; KYBER_PUBLIC_KEY_BYTES + 3] =
        [1u8; KYBER_PUBLIC_KEY_BYTES + 3];
    assert_eq!(
        encapsulate(&pk, &mut rng),
        Err(KyberLibError::InvalidInput)
    );
}

#[test]
fn keypair_decap_ct_wrong_size() {
    let ct: [u8; KYBER_CIPHERTEXT_BYTES + 3] =
        [1u8; KYBER_CIPHERTEXT_BYTES + 3];
    let sk: [u8; KYBER_SECRET_KEY_BYTES] =
        [1u8; KYBER_SECRET_KEY_BYTES];
    assert_eq!(decapsulate(&ct, &sk), Err(KyberLibError::InvalidInput));
}

#[test]
fn keypair_decap_sk_wrong_size() {
    let ct: [u8; KYBER_CIPHERTEXT_BYTES] =
        [1u8; KYBER_CIPHERTEXT_BYTES];
    let sk: [u8; KYBER_SECRET_KEY_BYTES + 3] =
        [1u8; KYBER_SECRET_KEY_BYTES + 3];
    assert_eq!(decapsulate(&ct, &sk), Err(KyberLibError::InvalidInput));
}

#[test]
fn keypair_failed_randombytes() {
    let mut rng = FailingRng::default();
    assert_eq!(
        keypair(&mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

#[test]
fn keypair_encap_failed_randombytes() {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        encapsulate(&keys.public, &mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

#[test]
fn public_from_private() {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let pk2 = public(&keys.secret);
    assert_eq!(pk2, keys.public);
}
