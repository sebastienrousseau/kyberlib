// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `kyberlib-hybrid`
//!
//! Hybrid post-quantum + classical KEMs built on `kyberlib`. Per
//! [`draft-ietf-tls-ecdhe-mlkem-04`][draft] (TLS hybrid KEMs, Feb 2026)
//! and the IETF hybrid KEM design [`draft-ietf-tls-hybrid-design-16`][design]:
//!
//! | Name                  | TLS codepoint | Classical | Post-quantum    |
//! |-----------------------|---------------|-----------|-----------------|
//! | `X25519MlKem768`      | `0x11EC`      | X25519    | ML-KEM-768      |
//! | `SecP256r1MlKem768`   | `0x11EB`      | NIST P-256| ML-KEM-768      |
//! | `SecP384r1MlKem1024`  | `0x11ED`      | NIST P-384| ML-KEM-1024     |
//!
//! [draft]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
//! [design]: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
//!
//! ## Implemented today
//!
//! [`X25519MlKem768`] is fully wired (Phase 5.1, issue #167) on top of
//! the FIPS 203 ML-KEM-768 primitives in `kyberlib` v0.0.7 and
//! `x25519-dalek` v2 for the classical side. The ECDHE-variants
//! `SecP256r1MlKem768` and `SecP384r1MlKem1024` are declared but the
//! ECDH choice is deferred — see issue #167 part b.
//!
//! ## Wire format
//!
//! Per draft-04, client and server orderings differ:
//!
//! ```text
//!   client_share := ek_mlkem (1184 B)  ‖  pk_x25519 (32 B)     = 1216 B
//!   server_share := pk_x25519 (32 B)   ‖  ct_mlkem (1088 B)    = 1120 B
//! ```
//!
//! The combined shared secret concatenates `ML-KEM-768.ss`
//! (32 B) || `X25519.ss` (32 B) → 64 B, which the consumer feeds
//! into TLS 1.3's HKDF.

#![cfg_attr(not(feature = "x25519"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Combined-share wire-format sizes per `draft-ietf-tls-ecdhe-mlkem-04`.
pub mod sizes {
    /// Client share for `X25519MlKem768`: ML-KEM-768 EncapKey || X25519 share.
    pub const X25519_MLKEM768_CLIENT_SHARE: usize = 1184 + 32;
    /// Server share for `X25519MlKem768`: X25519 share || ML-KEM-768 Ciphertext.
    pub const X25519_MLKEM768_SERVER_SHARE: usize = 32 + 1088;
    /// Combined shared secret length (ML-KEM-768.SS || X25519.SS).
    pub const X25519_MLKEM768_SHARED_SECRET: usize = 32 + 32;
}

/// Marker trait for hybrid KEM constructions. The concrete types
/// `X25519MlKem768`, `SecP256r1MlKem768`, `SecP384r1MlKem1024`
/// implement this. Sealed — third-party crates cannot extend.
pub trait Hybrid: sealed::Sealed {
    /// IETF codepoint per the TLS NamedGroup registry.
    const TLS_CODEPOINT: u16;
    /// Combined client-share length (PQ public + classical share).
    const CLIENT_SHARE_LEN: usize;
    /// Combined server-share length (classical share + PQ ciphertext).
    const SERVER_SHARE_LEN: usize;
    /// Combined shared-secret length.
    const SHARED_SECRET_LEN: usize;
}

/// Sealed pattern — only this crate implements [`Hybrid`].
mod sealed {
    /// Sealing trait for the hybrid KEM marker types.
    pub trait Sealed {}
}

// ============================================================================
// X25519MlKem768  (codepoint 0x11EC)
// ============================================================================

/// X25519 + ML-KEM-768 hybrid (TLS codepoint `0x11EC`).
///
/// See [the module-level docs](crate) for the wire format.
#[cfg(feature = "x25519")]
#[derive(Clone, Copy, Debug)]
pub struct X25519MlKem768;

#[cfg(feature = "x25519")]
impl sealed::Sealed for X25519MlKem768 {}

#[cfg(feature = "x25519")]
impl Hybrid for X25519MlKem768 {
    const TLS_CODEPOINT: u16 = 0x11EC;
    const CLIENT_SHARE_LEN: usize = sizes::X25519_MLKEM768_CLIENT_SHARE;
    const SERVER_SHARE_LEN: usize = sizes::X25519_MLKEM768_SERVER_SHARE;
    const SHARED_SECRET_LEN: usize =
        sizes::X25519_MLKEM768_SHARED_SECRET;
}

#[cfg(feature = "x25519")]
mod x25519_impl {
    use super::sizes::*;
    use core::fmt;
    use kyberlib::{
        KemCore, KyberLibError, MlKem768, MlKem768Ciphertext,
        MlKem768DecapKey, MlKem768EncapKey,
    };
    use rand_core::{CryptoRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Client-side decapsulation key for X25519MLKEM768: the
    /// ML-KEM-768 secret key plus the X25519 ephemeral secret.
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct X25519MlKem768Client {
        ml_kem_dk: MlKem768DecapKey,
        x25519_sk: StaticSecret,
    }

    impl fmt::Debug for X25519MlKem768Client {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("X25519MlKem768Client([REDACTED 2432 bytes])")
        }
    }

    impl X25519MlKem768Client {
        /// Generate a fresh client key pair and serialize the
        /// client_share for transmission.
        ///
        /// Returns `(client_state, client_share)` where:
        /// * `client_state` is retained by the caller for the
        ///   subsequent `decapsulate` step;
        /// * `client_share` is the wire-format byte string per draft-04:
        ///   ML-KEM-768 EncapKey (1184 B) ‖ X25519 PublicKey (32 B).
        pub fn generate<R: RngCore + CryptoRng>(
            rng: &mut R,
        ) -> Result<
            (Self, [u8; X25519_MLKEM768_CLIENT_SHARE]),
            KyberLibError,
        > {
            let (ml_kem_dk, ml_kem_ek) = MlKem768::generate(rng)?;
            let x25519_sk = StaticSecret::random_from_rng(&mut *rng);
            let x25519_pk = PublicKey::from(&x25519_sk);

            let mut share = [0u8; X25519_MLKEM768_CLIENT_SHARE];
            share[..1184].copy_from_slice(ml_kem_ek.as_bytes());
            share[1184..].copy_from_slice(x25519_pk.as_bytes());

            Ok((
                Self {
                    ml_kem_dk,
                    x25519_sk,
                },
                share,
            ))
        }

        /// Process the server's response and derive the 64-byte
        /// combined shared secret.
        ///
        /// `server_share` layout: X25519 PublicKey (32 B) ‖ ML-KEM-768
        /// Ciphertext (1088 B). Returns the concatenation
        /// `ML-KEM-768.ss ‖ X25519.ss` (32 + 32 = 64 B).
        ///
        /// # Errors
        ///
        /// Returns [`KyberLibError::InvalidInput`] if `server_share`
        /// is not exactly 1120 bytes.
        pub fn decapsulate(
            self,
            server_share: &[u8],
        ) -> Result<SharedSecret, KyberLibError> {
            if server_share.len() != X25519_MLKEM768_SERVER_SHARE {
                return Err(KyberLibError::InvalidInput);
            }
            let mut x25519_peer = [0u8; 32];
            x25519_peer.copy_from_slice(&server_share[..32]);
            let x25519_peer = PublicKey::from(x25519_peer);

            let ct = MlKem768Ciphertext::try_from_slice(
                &server_share[32..],
            )?;

            let ml_kem_ss = self.ml_kem_dk.decapsulate(&ct);
            let x25519_ss = self.x25519_sk.diffie_hellman(&x25519_peer);

            let mut combined = [0u8; X25519_MLKEM768_SHARED_SECRET];
            combined[..32].copy_from_slice(ml_kem_ss.as_bytes());
            combined[32..].copy_from_slice(x25519_ss.as_bytes());
            Ok(SharedSecret(combined))
        }
    }

    /// Server-side encapsulator: consumes the client's share and
    /// produces both the server's reply and the agreed-on shared
    /// secret.
    #[derive(Clone, Copy, Debug)]
    pub struct X25519MlKem768Server;

    impl X25519MlKem768Server {
        /// Decode the `client_share`, generate the server's X25519
        /// ephemeral, encapsulate against the client's ML-KEM-768 key,
        /// and return `(server_share, shared_secret)`.
        ///
        /// `client_share` layout: ML-KEM-768 EncapKey (1184 B) ‖
        /// X25519 PublicKey (32 B). `server_share` layout (returned):
        /// X25519 PublicKey (32 B) ‖ ML-KEM-768 Ciphertext (1088 B).
        ///
        /// # Errors
        ///
        /// Returns [`KyberLibError::InvalidInput`] if `client_share`
        /// is not exactly 1216 bytes, or
        /// [`KyberLibError::RandomBytesGeneration`] if the supplied
        /// RNG fails.
        #[allow(clippy::type_complexity)]
        pub fn encapsulate<R: RngCore + CryptoRng>(
            rng: &mut R,
            client_share: &[u8],
        ) -> Result<
            ([u8; X25519_MLKEM768_SERVER_SHARE], SharedSecret),
            KyberLibError,
        > {
            if client_share.len() != X25519_MLKEM768_CLIENT_SHARE {
                return Err(KyberLibError::InvalidInput);
            }
            // Decode the client share.
            let ek = MlKem768EncapKey::try_from_slice(
                &client_share[..1184],
            )?;

            let mut peer_pk_bytes = [0u8; 32];
            peer_pk_bytes.copy_from_slice(&client_share[1184..]);
            let peer_pk = PublicKey::from(peer_pk_bytes);

            // Server's X25519 ephemeral.
            let server_sk = StaticSecret::random_from_rng(&mut *rng);
            let server_pk = PublicKey::from(&server_sk);

            // Encapsulate against the client's ML-KEM key.
            let (ct, ml_kem_ss) = ek.encapsulate(rng)?;
            let x25519_ss = server_sk.diffie_hellman(&peer_pk);

            // Build the server_share.
            let mut server_share = [0u8; X25519_MLKEM768_SERVER_SHARE];
            server_share[..32].copy_from_slice(server_pk.as_bytes());
            server_share[32..].copy_from_slice(ct.as_bytes());

            // Build the combined shared secret.
            let mut combined = [0u8; X25519_MLKEM768_SHARED_SECRET];
            combined[..32].copy_from_slice(ml_kem_ss.as_bytes());
            combined[32..].copy_from_slice(x25519_ss.as_bytes());

            Ok((server_share, SharedSecret(combined)))
        }
    }

    /// 64-byte hybrid shared secret (`ML-KEM-768.ss || X25519.ss`).
    /// Zeroized on drop.
    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct SharedSecret([u8; X25519_MLKEM768_SHARED_SECRET]);

    impl SharedSecret {
        /// Borrow the raw 64 bytes (for feeding into TLS 1.3 HKDF, etc.).
        pub fn as_bytes(&self) -> &[u8; X25519_MLKEM768_SHARED_SECRET] {
            &self.0
        }
    }

    impl fmt::Debug for SharedSecret {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(
                "X25519MlKem768::SharedSecret([REDACTED 64 bytes])",
            )
        }
    }

    impl PartialEq for SharedSecret {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq for SharedSecret {}
}

#[cfg(feature = "x25519")]
pub use x25519_impl::{
    SharedSecret as X25519MlKem768SharedSecret, X25519MlKem768Client,
    X25519MlKem768Server,
};

// ============================================================================
// SecP256r1MlKem768 / SecP384r1MlKem1024  — declared, not yet implemented
// ============================================================================

/// SecP256r1 + ML-KEM-768 hybrid (TLS codepoint `0x11EB`).
///
/// **Not yet implemented** — see issue #167 part b for the
/// `p256`/`p384` dependency decision.
#[cfg(feature = "secp256r1")]
#[derive(Clone, Copy, Debug)]
pub struct SecP256r1MlKem768;

#[cfg(feature = "secp256r1")]
impl sealed::Sealed for SecP256r1MlKem768 {}

#[cfg(feature = "secp256r1")]
impl Hybrid for SecP256r1MlKem768 {
    const TLS_CODEPOINT: u16 = 0x11EB;
    const CLIENT_SHARE_LEN: usize = 1184 + 65;
    const SERVER_SHARE_LEN: usize = 65 + 1088;
    const SHARED_SECRET_LEN: usize = 32 + 32;
}

/// SecP384r1 + ML-KEM-1024 hybrid (TLS codepoint `0x11ED`).
///
/// **Not yet implemented** — see issue #167 part b.
#[cfg(feature = "secp384r1")]
#[derive(Clone, Copy, Debug)]
pub struct SecP384r1MlKem1024;

#[cfg(feature = "secp384r1")]
impl sealed::Sealed for SecP384r1MlKem1024 {}

#[cfg(feature = "secp384r1")]
impl Hybrid for SecP384r1MlKem1024 {
    const TLS_CODEPOINT: u16 = 0x11ED;
    const CLIENT_SHARE_LEN: usize = 1568 + 97;
    const SERVER_SHARE_LEN: usize = 97 + 1568;
    const SHARED_SECRET_LEN: usize = 32 + 48;
}

#[cfg(test)]
mod tests {
    // `super::*` is only used by tests gated on `feature = "x25519"`;
    // under `--no-default-features --features kyber768` (one of our
    // CI matrix cells) the cfg-gated tests vanish and the import
    // becomes unused.
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(feature = "x25519")]
    fn x25519_mlkem768_codepoint() {
        assert_eq!(X25519MlKem768::TLS_CODEPOINT, 0x11EC);
        assert_eq!(X25519MlKem768::CLIENT_SHARE_LEN, 1216);
        assert_eq!(X25519MlKem768::SERVER_SHARE_LEN, 1120);
        assert_eq!(X25519MlKem768::SHARED_SECRET_LEN, 64);
    }

    #[test]
    #[cfg(feature = "x25519")]
    fn x25519_mlkem768_round_trip() {
        let mut rng = rand::thread_rng();
        let (client, client_share) =
            X25519MlKem768Client::generate(&mut rng)
                .expect("client gen");
        assert_eq!(client_share.len(), 1216);

        let (server_share, server_ss) =
            X25519MlKem768Server::encapsulate(&mut rng, &client_share)
                .expect("server encap");
        assert_eq!(server_share.len(), 1120);
        assert_eq!(server_ss.as_bytes().len(), 64);

        let client_ss =
            client.decapsulate(&server_share).expect("client decap");
        assert_eq!(client_ss, server_ss);
    }

    #[test]
    #[cfg(feature = "x25519")]
    fn x25519_mlkem768_rejects_wrong_length_server_share() {
        let mut rng = rand::thread_rng();
        let (client, _) = X25519MlKem768Client::generate(&mut rng)
            .expect("client gen");
        let bad = vec![0u8; 1119]; // off by 1
        assert!(client.decapsulate(&bad).is_err());
    }
}
