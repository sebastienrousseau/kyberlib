// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PKCS#8 `OneAsymmetricKey` for ML-KEM decapsulation keys (RFC 9935 §6).

use crate::choice::{Choice, SEED_LEN};
use crate::params::{ct_eq, embedded_ek, Params};
use crate::public::{check_algorithm, PublicKey};
use core::fmt;
use kyberlib::{CryptoRng, KyberLibError, RngCore};
use pkcs8::{KeyError, PrivateKeyInfoRef};
use zeroize::Zeroizing;

/// Which RFC 9935 private-key form to write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateKeyFormat {
    /// `seed [0]`: the 64-byte seed `d ‖ z` only. RFC 9935 recommends
    /// it; it is also the smallest.
    Seed,
    /// `expandedKey`: the FIPS 203 decapsulation key only. The only
    /// form available for a key that was imported without its seed.
    Expanded,
    /// `both`: seed and expanded key. OpenSSL 3.5 writes this by default.
    Both,
}

/// An ML-KEM private key: the decapsulation key, its encapsulation key,
/// and the seed it came from when that is known.
///
/// Encodes to and decodes from PKCS#8 (DER, and PEM with the `pem`
/// feature) through [`pkcs8::EncodePrivateKey`] and
/// [`pkcs8::DecodePrivateKey`]. Decoding enforces RFC 9935 and FIPS 203:
///
/// - the OID must match `P` and the parameters field must be absent;
/// - the CHOICE variant is read from its tag, and sizes must be exact;
/// - an expanded key must pass the §7.3 hash check;
/// - in the `both` form, the expanded key must equal the one the seed
///   derives (otherwise the key is rejected as malformed);
/// - an optional `publicKey` field must match the derived key.
///
/// The seed is zeroized on drop; the decapsulation key zeroizes itself.
pub struct PrivateKey<P: Params> {
    seed: Option<Zeroizing<[u8; SEED_LEN]>>,
    dk: P::DecapsulationKey,
    ek: P::EncapsulationKey,
    format: PrivateKeyFormat,
}

impl<P: Params> PrivateKey<P> {
    /// Generates a key pair from a fresh 64-byte seed and keeps the seed.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::RandomBytesGeneration`] if the RNG fails.
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<Self, KyberLibError> {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rng.try_fill_bytes(seed.as_mut())
            .map_err(|_| KyberLibError::RandomBytesGeneration)?;
        Self::from_seed(&seed)
    }

    /// Derives the key pair from the seed `d ‖ z` (FIPS 203
    /// `ML-KEM.KeyGen_internal`). Writes the [`PrivateKeyFormat::Seed`]
    /// form by default.
    ///
    /// # Errors
    ///
    /// Propagates [`kyberlib::KemCore::generate_from_seed`] errors.
    pub fn from_seed(
        seed: &[u8; SEED_LEN],
    ) -> Result<Self, KyberLibError> {
        let (d, z) = seed.split_at(32);
        let d: &[u8; 32] =
            d.try_into().map_err(|_| KyberLibError::InvalidLength)?;
        let z: &[u8; 32] =
            z.try_into().map_err(|_| KyberLibError::InvalidLength)?;
        let (dk, ek) = P::generate_from_seed(d, z)?;
        Ok(Self {
            seed: Some(Zeroizing::new(*seed)),
            dk,
            ek,
            format: PrivateKeyFormat::Seed,
        })
    }

    /// Wraps an expanded decapsulation key with no seed. Runs the FIPS
    /// 203 §7.3 hash check. Writes [`PrivateKeyFormat::Expanded`].
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidKey`] if the hash check fails, or if the
    /// embedded encapsulation key fails the §7.2 check.
    pub fn from_expanded(
        dk: P::DecapsulationKey,
    ) -> Result<Self, KyberLibError> {
        let bytes = P::dk_bytes(&dk);
        P::dk_from_slice(bytes)?;
        let ek = P::ek_from_slice(embedded_ek::<P>(bytes))?;
        Ok(Self {
            seed: None,
            dk,
            ek,
            format: PrivateKeyFormat::Expanded,
        })
    }

    /// Chooses the form [`pkcs8::EncodePrivateKey`] writes.
    ///
    /// # Errors
    ///
    /// [`KyberLibError::InvalidKey`] when `Seed` or `Both` is asked for
    /// a key that has no seed.
    pub fn with_format(
        mut self,
        format: PrivateKeyFormat,
    ) -> Result<Self, KyberLibError> {
        if format != PrivateKeyFormat::Expanded && self.seed.is_none() {
            return Err(KyberLibError::InvalidKey);
        }
        self.format = format;
        Ok(self)
    }

    /// The form this key encodes to: the one it was decoded from, or
    /// the one chosen with [`Self::with_format`].
    pub const fn format(&self) -> PrivateKeyFormat {
        self.format
    }

    /// The seed `d ‖ z`, if known. Secret.
    pub fn seed(&self) -> Option<&[u8; SEED_LEN]> {
        self.seed.as_deref()
    }

    /// The decapsulation key.
    pub const fn decapsulation_key(&self) -> &P::DecapsulationKey {
        &self.dk
    }

    /// The encapsulation key.
    pub const fn encapsulation_key(&self) -> &P::EncapsulationKey {
        &self.ek
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey<P>
    where
        P::EncapsulationKey: Clone,
    {
        PublicKey::new(self.ek.clone())
    }

    fn from_choice(choice: &Choice<'_>) -> pkcs8::Result<Self> {
        let malformed =
            |_| pkcs8::Error::KeyMalformed(KeyError::Invalid);
        match *choice {
            Choice::Seed(seed) => {
                Self::from_seed(seed_array(seed)?).map_err(malformed)
            }
            Choice::Expanded(bytes) => P::dk_from_slice(bytes)
                .and_then(Self::from_expanded)
                .map_err(malformed),
            Choice::Both { seed, expanded } => {
                let key = Self::from_seed(seed_array(seed)?)
                    .map_err(malformed)?;
                if !ct_eq(P::dk_bytes(&key.dk), expanded) {
                    return Err(pkcs8::Error::KeyMalformed(
                        KeyError::Invalid,
                    ));
                }
                Ok(Self {
                    format: PrivateKeyFormat::Both,
                    ..key
                })
            }
        }
    }
}

fn seed_array(seed: &[u8]) -> pkcs8::Result<&[u8; SEED_LEN]> {
    seed.try_into()
        .map_err(|_| pkcs8::Error::KeyMalformed(KeyError::Invalid))
}

impl<P: Params> TryFrom<PrivateKeyInfoRef<'_>> for PrivateKey<P> {
    type Error = pkcs8::Error;

    fn try_from(info: PrivateKeyInfoRef<'_>) -> pkcs8::Result<Self> {
        check_algorithm::<P>(&info.algorithm)?;
        let choice =
            Choice::decode(info.private_key.as_bytes(), P::DK_LEN)?;
        let key = Self::from_choice(&choice)?;
        if let Some(pk) = info.public_key {
            let matches = pk.as_bytes() == Some(P::ek_bytes(&key.ek));
            if !matches {
                return Err(pkcs8::Error::KeyMalformed(
                    KeyError::Invalid,
                ));
            }
        }
        Ok(key)
    }
}

#[cfg(feature = "alloc")]
impl<P: Params> PrivateKey<P> {
    /// Builds the `PrivateKeyInfo` for this key in its chosen form and
    /// hands it to `f` (plain or encrypted encoding).
    pub(crate) fn with_info<T>(
        &self,
        f: impl FnOnce(&PrivateKeyInfoRef<'_>) -> pkcs8::Result<T>,
    ) -> pkcs8::Result<T> {
        let seed = self.seed.as_deref().map(<[u8; SEED_LEN]>::as_slice);
        let expanded = P::dk_bytes(&self.dk);
        let choice = match (self.format, seed) {
            (PrivateKeyFormat::Expanded, _) => {
                Choice::Expanded(expanded)
            }
            (PrivateKeyFormat::Seed, Some(seed)) => Choice::Seed(seed),
            (PrivateKeyFormat::Both, Some(seed)) => {
                Choice::Both { seed, expanded }
            }
            (_, None) => {
                return Err(pkcs8::Error::KeyMalformed(
                    KeyError::Invalid,
                ))
            }
        };
        let inner = crate::choice::encode(&choice)?;
        let info = PrivateKeyInfoRef::new(
            crate::public::algorithm::<P>(),
            der::asn1::OctetStringRef::new(&inner)?,
        );
        f(&info)
    }
}

#[cfg(feature = "alloc")]
impl<P: Params> pkcs8::EncodePrivateKey for PrivateKey<P> {
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        self.with_info(|info| {
            Ok(der::SecretDocument::encode_msg(info)?)
        })
    }
}

impl<P: Params> fmt::Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &P::ALGORITHM_ID)
            .field("format", &self.format)
            .field("seed", &self.seed.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}
