// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-pkcs8`
//!
//! PKCS#8, `SubjectPublicKeyInfo` and PEM encodings for kyberlib's
//! ML-KEM keys, as specified by
//! [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) (ML-KEM algorithm
//! identifiers for X.509). Keys interoperate with OpenSSL 3.5 and later:
//! `tests/openssl_interop.rs` decodes OpenSSL's output and re-encodes it
//! byte for byte.
//!
//! | Algorithm   | OID                      |
//! |-------------|--------------------------|
//! | ML-KEM-512  | `2.16.840.1.101.3.4.4.1` |
//! | ML-KEM-768  | `2.16.840.1.101.3.4.4.2` |
//! | ML-KEM-1024 | `2.16.840.1.101.3.4.4.3` |
//!
//! [`PrivateKey`] implements [`pkcs8::EncodePrivateKey`] and
//! [`pkcs8::DecodePrivateKey`]; [`PublicKey`] implements
//! [`spki::EncodePublicKey`] and [`spki::DecodePublicKey`]. With the
//! `pem` feature those traits add the PEM methods.
//!
//! ```
//! use kyberlib::MlKem768;
//! use kyberlib_pkcs8::{DecodePrivateKey, EncodePrivateKey, PrivateKey};
//!
//! let key = PrivateKey::<MlKem768>::generate(&mut rand::rngs::OsRng)
//!     .expect("RNG");
//! let der = key.to_pkcs8_der()?; // RFC 9935 seed form, 86 bytes
//! assert_eq!(der.as_bytes().len(), 86);
//! let back = PrivateKey::<MlKem768>::from_pkcs8_der(der.as_bytes())?;
//! assert_eq!(back.decapsulation_key(), key.decapsulation_key());
//! # Ok::<(), pkcs8::Error>(())
//! ```
//!
//! ## Private-key forms
//!
//! RFC 9935 defines three: the 64-byte seed, the expanded FIPS 203 key,
//! or both. Decoding accepts all three and checks them (see
//! [`PrivateKey`]). Encoding writes the seed form by default, as the RFC
//! recommends; pick another with [`PrivateKey::with_format`]. The
//! pre-standard "bare" layouts some early tools wrote are rejected.
//!
//! ## Password-encrypted keys
//!
//! With the `encryption` feature, `PrivateKey::decrypt_pkcs8_der` and
//! `decrypt_pkcs8_pem` read PBES2 `EncryptedPrivateKeyInfo` files
//! (PBKDF2 with HMAC-SHA-2, or scrypt; AES-CBC) as OpenSSL writes them, and
//! `PrivateKey::encrypt_to_pkcs8_der` / `encrypt_to_pkcs8_pem` write
//! them. Decryption refuses a file whose KDF cost exceeds
//! `DecryptLimits` before running the KDF.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod choice;
#[cfg(feature = "encryption")]
mod encrypted;
mod params;
mod private;
mod public;

/// IETF LAMPS object-identifier strings, re-exported from `kyberlib::oid`.
pub use kyberlib::oid;

pub use params::Params;
pub use private::{PrivateKey, PrivateKeyFormat};
pub use public::PublicKey;

#[cfg(feature = "encryption")]
pub use encrypted::DecryptLimits;

/// The RustCrypto crates this API is built on, for callers that need
/// their types (for example to inspect a `PrivateKeyInfo`).
pub use {der, pkcs8, spki};

pub use pkcs8::DecodePrivateKey;
#[cfg(feature = "pem")]
pub use pkcs8::LineEnding;
pub use spki::DecodePublicKey;
#[cfg(feature = "alloc")]
pub use {pkcs8::EncodePrivateKey, spki::EncodePublicKey};
