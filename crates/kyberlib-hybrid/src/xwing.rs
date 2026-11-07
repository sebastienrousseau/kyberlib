// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! X-Wing: a general-purpose hybrid KEM of ML-KEM-768 and X25519, per
//! [`draft-connolly-cfrg-xwing-kem-11`][xwing].
//!
//! Unlike the TLS groups in this crate, X-Wing is a complete KEM: it
//! hashes both component secrets, the X25519 ciphertext and public key
//! into one 32-byte secret with SHA3-256, so it can be used directly
//! (for example as the KEM in HPKE) without a TLS key schedule.
//!
//! ```text
//!   encapsulation key := pk_M (1184 B) ‖ pk_X (32 B)             = 1216 B
//!   ciphertext        := ct_M (1088 B) ‖ ct_X (32 B)             = 1120 B
//!   decapsulation key := 32-byte seed, expanded with SHAKE256
//!   shared secret     := SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\./" ‖ "/^\")
//! ```
//!
//! [xwing]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/

use core::fmt;
use kyberlib::{
    KemCore, KyberLibError, MlKem768, MlKem768Ciphertext,
    MlKem768DecapKey, MlKem768EncapKey,
};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Encapsulation key length in bytes.
pub const XWING_ENCAP_KEY_BYTES: usize = 1216;
/// Ciphertext length in bytes.
pub const XWING_CIPHERTEXT_BYTES: usize = 1120;
/// Decapsulation key (seed) length in bytes.
pub const XWING_SEED_BYTES: usize = 32;
/// Shared secret length in bytes.
pub const XWING_SHARED_SECRET_BYTES: usize = 32;

const ML_KEM_EK: usize = 1184;
const ML_KEM_CT: usize = 1088;
/// `XWingLabel`, the ASCII art `\./` `/^\` (hex `5c2e2f2f5e5c`).
const LABEL: &[u8; 6] = b"\\.//^\\";

/// X-Wing decapsulation key. Holds the 32-byte seed and caches its
/// expansion (draft §5.5.1). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub struct XWingDecapKey {
    seed: [u8; XWING_SEED_BYTES],
    sk_m: MlKem768DecapKey,
    sk_x: StaticSecret,
    #[zeroize(skip)]
    pk_x: [u8; 32],
}

impl fmt::Debug for XWingDecapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingDecapKey([REDACTED])")
    }
}

/// X-Wing encapsulation key: `pk_M ‖ pk_X`, 1216 bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct XWingEncapKey([u8; XWING_ENCAP_KEY_BYTES]);

impl fmt::Debug for XWingEncapKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingEncapKey([1216 bytes; not secret])")
    }
}

/// X-Wing ciphertext: `ct_M ‖ ct_X`, 1120 bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct XWingCiphertext([u8; XWING_CIPHERTEXT_BYTES]);

impl fmt::Debug for XWingCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingCiphertext([1120 bytes; opaque])")
    }
}

/// 32-byte X-Wing shared secret. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
#[non_exhaustive]
pub struct XWingSharedSecret([u8; XWING_SHARED_SECRET_BYTES]);

impl fmt::Debug for XWingSharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingSharedSecret([REDACTED 32 bytes])")
    }
}

impl XWingSharedSecret {
    /// Borrow the 32 secret bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_SHARED_SECRET_BYTES] {
        &self.0
    }
}

macro_rules! byte_wrapper {
    ($t:ident, $n:expr) => {
        impl $t {
            /// Wrap raw bytes.
            pub fn from_bytes(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }
            /// Copy from a slice, checking the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                let arr: [u8; $n] = bytes
                    .try_into()
                    .map_err(|_| KyberLibError::InvalidLength)?;
                Ok(Self(arr))
            }
            /// Borrow the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
        }
    };
}

byte_wrapper!(XWingEncapKey, XWING_ENCAP_KEY_BYTES);
byte_wrapper!(XWingCiphertext, XWING_CIPHERTEXT_BYTES);

impl XWingDecapKey {
    /// Generate a fresh key pair from 32 bytes of `rng` output.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self, XWingEncapKey), KyberLibError> {
        let mut seed = [0u8; XWING_SEED_BYTES];
        rng.try_fill_bytes(&mut seed)
            .map_err(|_| KyberLibError::RandomBytesGeneration)?;
        let pair = Self::from_seed(&seed);
        seed.zeroize();
        pair
    }

    /// Rebuild a key pair from its 32-byte seed
    /// (`GenerateKeyPairDerand`, draft §5.2.1).
    ///
    /// # Errors
    ///
    /// None in practice; mirrors [`KemCore::generate_from_seed`].
    pub fn from_seed(
        seed: &[u8; XWING_SEED_BYTES],
    ) -> Result<(Self, XWingEncapKey), KyberLibError> {
        let mut expanded = [0u8; 96];
        let mut xof = Shake256::default();
        xof.update(seed);
        xof.finalize_xof().read(&mut expanded);

        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        let mut sk_x_bytes = [0u8; 32];
        d.copy_from_slice(&expanded[..32]);
        z.copy_from_slice(&expanded[32..64]);
        sk_x_bytes.copy_from_slice(&expanded[64..]);
        expanded.zeroize();

        let keys = MlKem768::generate_from_seed(&d, &z);
        d.zeroize();
        z.zeroize();
        let (sk_m, pk_m) = keys?;

        let sk_x = StaticSecret::from(sk_x_bytes);
        sk_x_bytes.zeroize();
        let pk_x = *PublicKey::from(&sk_x).as_bytes();

        let mut ek = [0u8; XWING_ENCAP_KEY_BYTES];
        ek[..ML_KEM_EK].copy_from_slice(pk_m.as_bytes());
        ek[ML_KEM_EK..].copy_from_slice(&pk_x);

        let dk = Self {
            seed: *seed,
            sk_m,
            sk_x,
            pk_x,
        };
        Ok((dk, XWingEncapKey(ek)))
    }

    /// The 32-byte seed: the whole private key in storable form.
    pub fn seed(&self) -> &[u8; XWING_SEED_BYTES] {
        &self.seed
    }

    /// Decapsulate (draft §5.5). Never fails: ML-KEM's implicit
    /// rejection turns a bad ciphertext into an unrelated secret.
    #[must_use]
    pub fn decapsulate(
        &self,
        ct: &XWingCiphertext,
    ) -> XWingSharedSecret {
        let (ct_m_bytes, ct_x) = ct.0.split_at(ML_KEM_CT);
        let mut ct_m = [0u8; ML_KEM_CT];
        ct_m.copy_from_slice(ct_m_bytes);
        let ss_m = self
            .sk_m
            .decapsulate(&MlKem768Ciphertext::from_bytes(ct_m));

        let mut ct_x_arr = [0u8; 32];
        ct_x_arr.copy_from_slice(ct_x);
        let ss_x = self.sk_x.diffie_hellman(&PublicKey::from(ct_x_arr));
        combiner(
            ss_m.as_bytes(),
            ss_x.as_bytes(),
            &ct_x_arr,
            &self.pk_x,
        )
    }
}

impl XWingEncapKey {
    /// Encapsulate to this key (draft §5.4), drawing 64 bytes of `rng`
    /// output as the encapsulation seed. With kyberlib's `fips` feature
    /// the ML-KEM half takes its message from the AWS-LC DRBG instead
    /// of the seed, so the result is correct but not reproducible from
    /// `rng`.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidKey`] if the ML-KEM half fails the FIPS
    /// 203 §7.2 check; [`KyberLibError::RandomBytesGeneration`] if the
    /// RNG fails.
    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(XWingCiphertext, XWingSharedSecret), KyberLibError>
    {
        let mut eseed = [0u8; 64];
        rng.try_fill_bytes(&mut eseed)
            .map_err(|_| KyberLibError::RandomBytesGeneration)?;
        let out = self.encapsulate_derand(&eseed);
        eseed.zeroize();
        out
    }

    /// `EncapsulateDerand` (draft §5.4.1): `eseed[..32]` is the ML-KEM
    /// message, `eseed[32..]` the X25519 ephemeral secret.
    fn encapsulate_derand(
        &self,
        eseed: &[u8; 64],
    ) -> Result<(XWingCiphertext, XWingSharedSecret), KyberLibError>
    {
        let pk_m =
            MlKem768EncapKey::try_from_slice(&self.0[..ML_KEM_EK])?;
        let mut pk_x = [0u8; 32];
        pk_x.copy_from_slice(&self.0[ML_KEM_EK..]);

        let mut ek_x_bytes = [0u8; 32];
        ek_x_bytes.copy_from_slice(&eseed[32..]);
        let ek_x = StaticSecret::from(ek_x_bytes);
        ek_x_bytes.zeroize();
        let ct_x = *PublicKey::from(&ek_x).as_bytes();
        let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));

        let mut message = OneShot::new(&eseed[..32]);
        let (ct_m, ss_m) = pk_m.encapsulate(&mut message)?;

        let mut ct = [0u8; XWING_CIPHERTEXT_BYTES];
        ct[..ML_KEM_CT].copy_from_slice(ct_m.as_bytes());
        ct[ML_KEM_CT..].copy_from_slice(&ct_x);
        let ss =
            combiner(ss_m.as_bytes(), ss_x.as_bytes(), &ct_x, &pk_x);
        Ok((XWingCiphertext(ct), ss))
    }
}

/// The X-Wing combiner (draft §5.3).
fn combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> XWingSharedSecret {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, LABEL);
    XWingSharedSecret(h.finalize().into())
}

/// Hands kyberlib's encapsulation exactly the 32-byte message taken
/// from the caller's encapsulation seed, once. Any further draw fails,
/// so a change in how much randomness ML-KEM consumes shows up as an
/// error instead of a silently different construction.
struct OneShot<'a> {
    bytes: Option<&'a [u8]>,
}

impl<'a> OneShot<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes: Some(bytes) }
    }
}

impl CryptoRng for OneShot<'_> {}

impl RngCore for OneShot<'_> {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let _ = self.try_fill_bytes(dest);
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        match self.bytes.take() {
            Some(b) if b.len() == dest.len() => {
                dest.copy_from_slice(b);
                Ok(())
            }
            _ => Err(ONESHOT_EXHAUSTED.into()),
        }
    }
}

const ONESHOT_EXHAUSTED: core::num::NonZeroU32 =
    match core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START) {
        Some(code) => code,
        None => core::num::NonZeroU32::MIN,
    };

#[cfg(test)]
mod tests {
    use super::*;

    struct XWingVector {
        seed: &'static str,
        sk: &'static str,
        pk: &'static str,
        eseed: &'static str,
        ct: &'static str,
        ss: &'static str,
    }

    mod vectors {
        use super::XWingVector;
        include!("../tests/vectors/xwing_draft11.rs");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn label_matches_draft_hex() {
        assert_eq!(LABEL, &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    }

    /// draft-connolly-cfrg-xwing-kem-11 Appendix C, all three vectors:
    /// key derivation, derandomised encapsulation and decapsulation.
    #[test]
    fn draft_11_test_vectors() {
        for (i, v) in vectors::VECTORS.iter().enumerate() {
            let seed: [u8; 32] = unhex(v.seed).try_into().unwrap();
            let (dk, ek) = XWingDecapKey::from_seed(&seed).unwrap();
            assert_eq!(
                dk.seed()[..],
                unhex(v.sk)[..],
                "vector {i}: sk"
            );
            assert_eq!(
                ek.as_bytes()[..],
                unhex(v.pk)[..],
                "vector {i}: pk"
            );

            // Decapsulating the draft's ciphertext is deterministic on
            // every backend.
            let ct =
                XWingCiphertext::try_from_slice(&unhex(v.ct)).unwrap();
            assert_eq!(
                dk.decapsulate(&ct).as_bytes()[..],
                unhex(v.ss)[..],
                "vector {i}: decaps"
            );

            // Derandomised encapsulation needs ML-KEM to take its message
            // from eseed. kyberlib's `fips` backend draws it from the
            // AWS-LC DRBG instead, as an approved module must.
            if kyberlib::BACKEND.contains("FIPS") {
                continue;
            }
            let eseed: [u8; 64] = unhex(v.eseed).try_into().unwrap();
            let (ct2, ss) = ek.encapsulate_derand(&eseed).unwrap();
            assert_eq!(ct2, ct, "vector {i}: ct");
            assert_eq!(
                ss.as_bytes()[..],
                unhex(v.ss)[..],
                "vector {i}: ss"
            );
        }
    }
}
