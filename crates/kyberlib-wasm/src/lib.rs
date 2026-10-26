// Copyright © 2024-2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-wasm`
//!
//! WebAssembly bindings for [`kyberlib`]. Exposes the KEM API
//! (`keypair`, `encapsulate`, `decapsulate`) and the parameter
//! constants as JS-callable functions via `wasm-bindgen`.
//!
//! Split out from the main `kyberlib` crate in v0.0.7 (issue #144) so
//! the safe core has no `wasm-bindgen` dependency and can stay
//! `#![forbid(unsafe_code)]` under default features.

#![allow(non_snake_case)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;
use kyberlib::{
    KyberLibError, KYBER_CIPHERTEXT_BYTES, KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES, KYBER_SHARED_SECRET_BYTES,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Generate a key pair for Kyber encryption.
///
/// # Errors
///
/// Returns a `JsError` if an error occurs during key pair generation.
#[wasm_bindgen]
pub fn keypair() -> Result<Keys, JsError> {
    let mut rng = OsRng {};
    match kyberlib::keypair(&mut rng) {
        Ok(keys) => Ok(Keys {
            pubkey: Box::new(keys.public),
            secret: Box::new(keys.secret),
        }),
        Err(KyberLibError::RandomBytesGeneration) => {
            Err(JsError::new("Error trying to fill random bytes"))
        }
        _ => Err(JsError::new("The keypair could not be generated")),
    }
}

/// Encapsulate a shared secret using the provided public key.
///
/// # Arguments
///
/// * `pk` - The public key as a boxed slice of bytes.
///
/// # Errors
///
/// Returns a `JsValue` that is `null()` if the public key size is incorrect or if an error occurs during encapsulation.
#[wasm_bindgen]
pub fn encapsulate(pk: Box<[u8]>) -> Result<Kex, JsValue> {
    if pk.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(JsValue::null());
    }

    let mut rng = OsRng {};
    match kyberlib::encapsulate(&pk, &mut rng) {
        Ok(kex) => Ok(Kex {
            ciphertext: Box::new(kex.0),
            sharedSecret: Box::new(kex.1),
        }),
        Err(_) => Err(JsValue::null()),
    }
}

/// Decapsulate a ciphertext using the provided secret key.
///
/// # Arguments
///
/// * `ct` - The ciphertext as a boxed slice of bytes.
/// * `sk` - The secret key as a boxed slice of bytes.
///
/// # Errors
///
/// Returns a `JsValue` that is `null()` if the input sizes are incorrect or if an error occurs during decapsulation.
#[wasm_bindgen]
pub fn decapsulate(
    ct: Box<[u8]>,
    sk: Box<[u8]>,
) -> Result<Box<[u8]>, JsValue> {
    if ct.len() != KYBER_CIPHERTEXT_BYTES
        || sk.len() != KYBER_SECRET_KEY_BYTES
    {
        return Err(JsValue::null());
    }

    match kyberlib::decapsulate(&ct, &sk) {
        Ok(ss) => Ok(Box::new(ss)),
        Err(_) => Err(JsValue::null()),
    }
}

/// Represents Kyber key pair.
#[wasm_bindgen]
pub struct Keys {
    pubkey: Box<[u8]>,
    secret: Box<[u8]>,
}

/// Represents Kyber encapsulated shared secret.
#[wasm_bindgen]
pub struct Kex {
    ciphertext: Box<[u8]>,
    sharedSecret: Box<[u8]>,
}

/// Prints a buffer as its length only, in the format the kyberlib
/// ML-KEM types use: `[N bytes; not secret]` or `[REDACTED N bytes]`.
struct Redacted {
    len: usize,
    secret: bool,
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.secret {
            write!(f, "[REDACTED {} bytes]", self.len)
        } else {
            write!(f, "[{} bytes; not secret]", self.len)
        }
    }
}

/// Redacts the secret key; the public key is shown by length.
impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field(
                "pubkey",
                &Redacted {
                    len: self.pubkey.len(),
                    secret: false,
                },
            )
            .field(
                "secret",
                &Redacted {
                    len: self.secret.len(),
                    secret: true,
                },
            )
            .finish()
    }
}

/// Redacts the shared secret; the ciphertext is shown by length.
impl fmt::Debug for Kex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kex")
            .field(
                "ciphertext",
                &Redacted {
                    len: self.ciphertext.len(),
                    secret: false,
                },
            )
            .field(
                "sharedSecret",
                &Redacted {
                    len: self.sharedSecret.len(),
                    secret: true,
                },
            )
            .finish()
    }
}

#[wasm_bindgen]
impl Keys {
    /// Create a new key pair.
    ///
    /// This function generates a new Kyber key pair and returns it as a `Keys` struct.
    ///
    /// # Errors
    ///
    /// Returns a `JsError` if an error occurs during key pair generation.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Keys, JsError> {
        keypair()
    }

    /// Get the public key.
    ///
    /// Returns the public key as a boxed slice of bytes.
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> Box<[u8]> {
        self.pubkey.clone()
    }

    /// Get the secret key.
    ///
    /// Returns the secret key as a boxed slice of bytes.
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Box<[u8]> {
        self.secret.clone()
    }
}

#[wasm_bindgen]
impl Kex {
    /// Create a new Kex instance by encapsulating with a given public key.
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key as a boxed slice of bytes.
    ///
    /// # Panics
    ///
    /// Panics if the public key size is incorrect.
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: Box<[u8]>) -> Self {
        encapsulate(public_key).expect("Invalid Public Key Size")
    }

    /// Get the ciphertext.
    ///
    /// Returns the ciphertext as a boxed slice of bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Box<[u8]> {
        self.ciphertext.clone()
    }

    /// Get the shared secret.
    ///
    /// Returns the shared secret as a boxed slice of bytes.
    #[wasm_bindgen(getter)]
    pub fn sharedSecret(&self) -> Box<[u8]> {
        self.sharedSecret.clone()
    }

    /// Set the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext as a boxed slice of bytes.
    #[wasm_bindgen(setter)]
    pub fn set_ciphertext(&mut self, ciphertext: Box<[u8]>) {
        self.ciphertext = ciphertext;
    }

    /// Set the shared secret.
    ///
    /// # Arguments
    ///
    /// * `sharedSecret` - The shared secret as a boxed slice of bytes.
    #[wasm_bindgen(setter)]
    pub fn set_sharedSecret(&mut self, sharedSecret: Box<[u8]>) {
        self.sharedSecret = sharedSecret;
    }
}

/// Represents Kyber parameters.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Params {
    /// The size of public key bytes.
    #[wasm_bindgen(readonly)]
    pub publicKeyBytes: usize,
    /// The size of secret key bytes.
    #[wasm_bindgen(readonly)]
    pub secretKeyBytes: usize,
    /// The size of ciphertext bytes.
    #[wasm_bindgen(readonly)]
    pub ciphertextBytes: usize,
    /// The size of shared secret bytes.
    #[wasm_bindgen(readonly)]
    pub sharedSecretBytes: usize,
}

#[wasm_bindgen]
impl Params {
    /// Get the size of public key bytes.
    #[wasm_bindgen(getter)]
    pub fn publicKeyBytes() -> usize {
        KYBER_PUBLIC_KEY_BYTES
    }

    /// Get the size of secret key bytes.
    #[wasm_bindgen(getter)]
    pub fn secretKeyBytes() -> usize {
        KYBER_SECRET_KEY_BYTES
    }

    /// Get the size of ciphertext bytes.
    #[wasm_bindgen(getter)]
    pub fn ciphertextBytes() -> usize {
        KYBER_CIPHERTEXT_BYTES
    }

    /// Get the size of shared secret bytes.
    #[wasm_bindgen(getter)]
    pub fn sharedSecretBytes() -> usize {
        KYBER_SHARED_SECRET_BYTES
    }
}
