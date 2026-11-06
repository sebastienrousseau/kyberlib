// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! NIST-curve TLS hybrids per `draft-ietf-tls-ecdhe-mlkem`:
//! `SecP256r1MLKEM768` (0x11EB) and `SecP384r1MLKEM1024` (0x11ED).
//!
//! Unlike X25519MLKEM768, both groups put the ECDH component first:
//!
//! ```text
//!   client_share := ecdh_point ‖ ek_mlkem
//!   server_share := ecdh_point ‖ ct_mlkem
//!   shared       := ecdh_x     ‖ ss_mlkem
//! ```
//!
//! ECDH points are SEC 1 uncompressed (`0x04 ‖ X ‖ Y`); the ECDH secret
//! is the X coordinate (RFC 8446 §7.4.2). Points are validated as on
//! the curve and not the identity; the server runs the FIPS 203 §7.2
//! check on the ML-KEM key.

use core::fmt;
use kyberlib::KyberLibError;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

macro_rules! secp_hybrid {
    (
        $doc:literal,
        curve: $curve:ident, parse: $parse:ident,
        kem: $kem:ident, ek: $ek:ident, dk: $dk:ident, ct: $ct:ident,
        client: $client:ident, server: $server:ident, secret: $secret:ident,
        point: $point:expr, ek_len: $ek_len:expr, ct_len: $ct_len:expr,
        ecdh_len: $ecdh_len:expr
    ) => {
        #[doc = concat!("Client state for ", $doc, ": ECDH ephemeral plus ML-KEM key.")]
        pub struct $client {
            ecdh: $curve::ecdh::EphemeralSecret,
            ml_kem_dk: kyberlib::$dk,
        }

        impl fmt::Debug for $client {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($client), "([REDACTED])"))
            }
        }

        #[doc = concat!("Server side of ", $doc, ".")]
        #[derive(Clone, Copy, Debug)]
        pub struct $server;

        #[doc = concat!("Shared secret for ", $doc, ": ECDH X ‖ ML-KEM secret. Zeroized on drop.")]
        #[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
        pub struct $secret([u8; $ecdh_len + 32]);

        impl fmt::Debug for $secret {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($secret), "([REDACTED])"))
            }
        }

        impl $secret {
            /// Borrow the raw bytes (input to the TLS 1.3 key schedule).
            pub fn as_bytes(&self) -> &[u8; $ecdh_len + 32] {
                &self.0
            }

            fn join(ecdh: &[u8], ml_kem: &[u8; 32]) -> Self {
                let mut out = [0u8; $ecdh_len + 32];
                out[..$ecdh_len].copy_from_slice(ecdh);
                out[$ecdh_len..].copy_from_slice(ml_kem);
                Self(out)
            }
        }

        impl $client {
            /// Generate client keys and the client share
            /// (`ecdh_point ‖ ek_mlkem`).
            ///
            /// # Errors
            ///
            /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
            pub fn generate<R: RngCore + CryptoRng>(
                rng: &mut R,
            ) -> Result<(Self, [u8; $point + $ek_len]), KyberLibError> {
                use kyberlib::KemCore;
                use $curve::elliptic_curve::sec1::ToEncodedPoint;
                let (ml_kem_dk, ml_kem_ek) = kyberlib::$kem::generate(rng)?;
                let ecdh = $curve::ecdh::EphemeralSecret::random(&mut *rng);
                let mut share = [0u8; $point + $ek_len];
                share[..$point].copy_from_slice(
                    ecdh.public_key().to_encoded_point(false).as_bytes(),
                );
                share[$point..].copy_from_slice(ml_kem_ek.as_bytes());
                Ok((Self { ecdh, ml_kem_dk }, share))
            }

            /// Process the server share (`ecdh_point ‖ ct_mlkem`).
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidInput`] on a wrong length;
            /// [`KyberLibError::InvalidKey`] if the point is invalid.
            pub fn decapsulate(
                self,
                server_share: &[u8],
            ) -> Result<$secret, KyberLibError> {
                if server_share.len() != $point + $ct_len {
                    return Err(KyberLibError::InvalidInput);
                }
                let peer = $parse(&server_share[..$point])?;
                let ct = kyberlib::$ct::try_from_slice(&server_share[$point..])?;
                let ecdh = self.ecdh.diffie_hellman(&peer);
                let ml_kem = self.ml_kem_dk.decapsulate(&ct);
                Ok($secret::join(ecdh.raw_secret_bytes(), ml_kem.as_bytes()))
            }
        }

        impl $server {
            /// Answer a client share: returns the server share
            /// (`ecdh_point ‖ ct_mlkem`) and the shared secret.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidInput`] on a wrong length;
            /// [`KyberLibError::InvalidKey`] if the point is invalid or
            /// the ML-KEM key fails the FIPS 203 §7.2 check;
            /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
            #[allow(clippy::type_complexity)]
            pub fn encapsulate<R: RngCore + CryptoRng>(
                rng: &mut R,
                client_share: &[u8],
            ) -> Result<([u8; $point + $ct_len], $secret), KyberLibError> {
                if client_share.len() != $point + $ek_len {
                    return Err(KyberLibError::InvalidInput);
                }
                use $curve::elliptic_curve::sec1::ToEncodedPoint;
                let peer = $parse(&client_share[..$point])?;
                let ek = kyberlib::$ek::try_from_slice(&client_share[$point..])?;
                let (ct, ml_kem) = ek.encapsulate(rng)?;
                let ecdh_sk = $curve::ecdh::EphemeralSecret::random(&mut *rng);
                let ecdh = ecdh_sk.diffie_hellman(&peer);

                let mut share = [0u8; $point + $ct_len];
                share[..$point].copy_from_slice(
                    ecdh_sk.public_key().to_encoded_point(false).as_bytes(),
                );
                share[$point..].copy_from_slice(ct.as_bytes());
                Ok((share, $secret::join(ecdh.raw_secret_bytes(), ml_kem.as_bytes())))
            }
        }
    };
}

macro_rules! point_parser {
    ($name:ident, $curve:ident) => {
        /// Decode a SEC 1 uncompressed point, rejecting compressed
        /// encodings, off-curve points and the identity.
        fn $name(
            bytes: &[u8],
        ) -> Result<$curve::PublicKey, KyberLibError> {
            if bytes.first() != Some(&0x04) {
                return Err(KyberLibError::InvalidKey);
            }
            $curve::PublicKey::from_sec1_bytes(bytes)
                .map_err(|_| KyberLibError::InvalidKey)
        }
    };
}

#[cfg(feature = "secp256r1")]
point_parser!(parse_point_p256, p256);
#[cfg(feature = "secp384r1")]
point_parser!(parse_point_p384, p384);

#[cfg(feature = "secp256r1")]
secp_hybrid!(
    "SecP256r1MLKEM768 (TLS 0x11EB)",
    curve: p256, parse: parse_point_p256,
    kem: MlKem768, ek: MlKem768EncapKey, dk: MlKem768DecapKey, ct: MlKem768Ciphertext,
    client: SecP256r1MlKem768Client, server: SecP256r1MlKem768Server,
    secret: SecP256r1MlKem768SharedSecret,
    point: 65, ek_len: 1184, ct_len: 1088, ecdh_len: 32
);

#[cfg(feature = "secp384r1")]
secp_hybrid!(
    "SecP384r1MLKEM1024 (TLS 0x11ED)",
    curve: p384, parse: parse_point_p384,
    kem: MlKem1024, ek: MlKem1024EncapKey, dk: MlKem1024DecapKey, ct: MlKem1024Ciphertext,
    client: SecP384r1MlKem1024Client, server: SecP384r1MlKem1024Server,
    secret: SecP384r1MlKem1024SharedSecret,
    point: 97, ek_len: 1568, ct_len: 1568, ecdh_len: 48
);
