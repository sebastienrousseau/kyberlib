// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Writes an ML-KEM-768 key pair as PEM and reads it back.
//!
//! `cargo run -p kyberlib-pkcs8 --example pem_roundtrip --features pem`
//!
//! The output loads in OpenSSL 3.5+:
//! `openssl pkey -in private.pem -text -noout`.

use kyberlib::MlKem768;
use kyberlib_pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey,
    EncodePublicKey, LineEnding, PrivateKey, PublicKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = PrivateKey::<MlKem768>::generate(&mut rand::rngs::OsRng)?;
    let private_pem = key.to_pkcs8_pem(LineEnding::LF)?;
    let public_pem =
        key.public_key().to_public_key_pem(LineEnding::LF)?;
    println!("{public_pem}");

    let back = PrivateKey::<MlKem768>::from_pkcs8_pem(&private_pem)?;
    let public =
        PublicKey::<MlKem768>::from_public_key_pem(&public_pem)?;
    assert_eq!(back.decapsulation_key(), key.decapsulation_key());
    assert_eq!(public.key(), key.encapsulation_key());
    println!(
        "private key: {} bytes of PEM ({:?} form)",
        private_pem.len(),
        back.format()
    );
    Ok(())
}
