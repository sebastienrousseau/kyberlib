// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Password-encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, PBES2 from
//! RFC 8018) for ML-KEM private keys.
//!
//! Decryption runs a password-based key-derivation function whose cost
//! is set by the file. A hostile file could ask for billions of PBKDF2
//! iterations or gigabytes of scrypt memory, so these functions check
//! the parameters against [`DecryptLimits`] first and refuse the file
//! without running the KDF.

use crate::params::Params;
use crate::private::PrivateKey;
use kyberlib::{CryptoRng, RngCore};
use pkcs8::pkcs5::{self, pbes2};
use pkcs8::rand_core::{TryCryptoRng, TryRng};
use pkcs8::{EncryptedPrivateKeyInfoRef, SecretDocument};

/// Ceilings on the work a file may ask decryption to do.
///
/// The defaults accept what OpenSSL 3.5 and this crate write (PBKDF2
/// with up to OWASP's 600,000 iterations and well beyond; scrypt with
/// OpenSSL's 32 MiB memory ceiling and beyond) and refuse costs meant
/// to stall or exhaust the process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DecryptLimits {
    /// Most PBKDF2 iterations accepted. Default 10,000,000.
    pub max_pbkdf2_iterations: u32,
    /// Most scrypt memory accepted, `128 * r * N` bytes. Default 256 MiB.
    pub max_scrypt_memory: u64,
    /// Most scrypt parallelism `p` accepted (each lane repeats the
    /// memory-hard work). Default 16.
    pub max_scrypt_parallelization: u16,
}

impl Default for DecryptLimits {
    fn default() -> Self {
        Self {
            max_pbkdf2_iterations: 10_000_000,
            max_scrypt_memory: 256 << 20,
            max_scrypt_parallelization: 16,
        }
    }
}

impl DecryptLimits {
    /// Sets the most PBKDF2 iterations accepted.
    #[must_use]
    pub const fn with_max_pbkdf2_iterations(mut self, n: u32) -> Self {
        self.max_pbkdf2_iterations = n;
        self
    }

    /// Sets the most scrypt memory accepted, in bytes (`128 * r * N`).
    #[must_use]
    pub const fn with_max_scrypt_memory(mut self, bytes: u64) -> Self {
        self.max_scrypt_memory = bytes;
        self
    }

    /// Sets the most scrypt parallelism `p` accepted.
    #[must_use]
    pub const fn with_max_scrypt_parallelization(
        mut self,
        p: u16,
    ) -> Self {
        self.max_scrypt_parallelization = p;
        self
    }

    /// Refuses a scheme whose KDF costs exceed the limits, or that is
    /// not PBES2.
    fn check(
        &self,
        scheme: &pkcs5::EncryptionScheme,
    ) -> pkcs8::Result<()> {
        let pkcs5::EncryptionScheme::Pbes2(params) = scheme else {
            return Err(pkcs5::Error::UnsupportedAlgorithm {
                oid: scheme.oid(),
            }
            .into());
        };
        let within = match &params.kdf {
            pbes2::Kdf::Pbkdf2(k) => {
                k.iteration_count <= self.max_pbkdf2_iterations
            }
            pbes2::Kdf::Scrypt(k) => self.scrypt_within(
                k.cost_parameter,
                k.block_size,
                k.parallelization,
            ),
            // A KDF this version does not know: refuse rather than guess its cost.
            _ => false,
        };
        if within {
            Ok(())
        } else {
            Err(pkcs5::Error::AlgorithmParametersInvalid {
                oid: params.kdf.oid(),
            }
            .into())
        }
    }

    /// scrypt needs `128 * r * N` bytes; each of `p` lanes repeats it.
    fn scrypt_within(&self, n: u64, r: u16, p: u16) -> bool {
        let memory = 128 * u128::from(r) * u128::from(n);
        memory <= u128::from(self.max_scrypt_memory)
            && p <= self.max_scrypt_parallelization
    }
}

impl<P: Params> PrivateKey<P> {
    /// Decrypts and decodes a DER `EncryptedPrivateKeyInfo` with the
    /// default [`DecryptLimits`], then applies every check
    /// [`pkcs8::DecodePrivateKey::from_pkcs8_der`] applies.
    ///
    /// Prefer this to the trait method
    /// `DecodePrivateKey::from_pkcs8_encrypted_der`, which runs whatever
    /// KDF cost the file names.
    ///
    /// # Errors
    ///
    /// A malformed document, a KDF cost over the limits, a wrong
    /// password, or a decrypted key that fails decoding.
    pub fn decrypt_pkcs8_der(
        der: &[u8],
        password: impl AsRef<[u8]>,
    ) -> pkcs8::Result<Self> {
        Self::decrypt_pkcs8_der_with_limits(
            der,
            password,
            &DecryptLimits::default(),
        )
    }

    /// [`Self::decrypt_pkcs8_der`] with explicit limits.
    ///
    /// # Errors
    ///
    /// As [`Self::decrypt_pkcs8_der`].
    pub fn decrypt_pkcs8_der_with_limits(
        der: &[u8],
        password: impl AsRef<[u8]>,
        limits: &DecryptLimits,
    ) -> pkcs8::Result<Self> {
        use pkcs8::DecodePrivateKey;
        let info = EncryptedPrivateKeyInfoRef::try_from(der)?;
        limits.check(&info.encryption_algorithm)?;
        let doc = info.decrypt(password)?;
        <Self as DecodePrivateKey>::from_pkcs8_der(doc.as_bytes())
    }

    /// Decrypts a PEM `ENCRYPTED PRIVATE KEY` with the default
    /// [`DecryptLimits`].
    ///
    /// # Errors
    ///
    /// A wrong PEM label, or as [`Self::decrypt_pkcs8_der`].
    #[cfg(feature = "pem")]
    pub fn decrypt_pkcs8_pem(
        pem: &str,
        password: impl AsRef<[u8]>,
    ) -> pkcs8::Result<Self> {
        use der::pem::PemLabel;
        let (label, doc) = der::Document::from_pem(pem)?;
        EncryptedPrivateKeyInfoRef::validate_pem_label(label)?;
        Self::decrypt_pkcs8_der(doc.as_bytes(), password)
    }

    /// Encrypts this key as PKCS#8 with PBES2: scrypt (`N` = 2^14,
    /// `r` = 8, `p` = 1) and AES-256-CBC, settings OpenSSL 3 reads. The
    /// salt and IV come from `rng`.
    ///
    /// # Errors
    ///
    /// An RNG failure, or an encoding error.
    pub fn encrypt_to_pkcs8_der<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        password: impl AsRef<[u8]>,
    ) -> pkcs8::Result<SecretDocument> {
        let mut rng = Rng06(rng);
        self.with_info(|info| info.encrypt_with_rng(&mut rng, password))
    }

    /// [`Self::encrypt_to_pkcs8_der`] as PEM (`ENCRYPTED PRIVATE KEY`).
    ///
    /// # Errors
    ///
    /// As [`Self::encrypt_to_pkcs8_der`].
    #[cfg(feature = "pem")]
    pub fn encrypt_to_pkcs8_pem<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        password: impl AsRef<[u8]>,
        line_ending: pkcs8::LineEnding,
    ) -> pkcs8::Result<zeroize::Zeroizing<alloc::string::String>> {
        use der::pem::PemLabel;
        let doc = self.encrypt_to_pkcs8_der(rng, password)?;
        Ok(doc.to_pem(
            EncryptedPrivateKeyInfoRef::PEM_LABEL,
            line_ending,
        )?)
    }
}

/// Adapts kyberlib's `rand_core` 0.6 RNG to the `rand_core` 0.10 traits
/// `pkcs8` uses, so one RNG type serves the whole crate.
struct Rng06<'a, R>(&'a mut R);

/// The wrapped RNG failed.
#[derive(Debug)]
struct RngFailure;

impl core::fmt::Display for RngFailure {
    fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
    ) -> core::fmt::Result {
        f.write_str("RNG failure")
    }
}

impl core::error::Error for RngFailure {}

impl<R: RngCore + CryptoRng> TryRng for Rng06<'_, R> {
    type Error = RngFailure;

    fn try_next_u32(&mut self) -> Result<u32, RngFailure> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, RngFailure> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(
        &mut self,
        dst: &mut [u8],
    ) -> Result<(), RngFailure> {
        self.0.try_fill_bytes(dst).map_err(|_| RngFailure)
    }
}

impl<R: RngCore + CryptoRng> TryCryptoRng for Rng06<'_, R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use kyberlib::MlKem512;

    /// An RNG that always fails.
    struct Broken;

    impl RngCore for Broken {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            unreachable!()
        }
        fn try_fill_bytes(
            &mut self,
            _: &mut [u8],
        ) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::from(
                core::num::NonZeroU32::new(
                    rand_core::Error::CUSTOM_START,
                )
                .unwrap(),
            ))
        }
    }

    impl CryptoRng for Broken {}

    #[test]
    fn rng_failure_is_an_error_not_a_weak_salt() {
        let key = PrivateKey::<MlKem512>::from_seed(&[7; 64]).unwrap();
        let err =
            key.encrypt_to_pkcs8_der(&mut Broken, "pw").unwrap_err();
        assert_eq!(
            err,
            pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::Rng)
        );
    }

    #[test]
    fn scrypt_limit_boundaries() {
        let limits = DecryptLimits::default();
        assert!(limits.scrypt_within(1 << 14, 8, 1)); // OpenSSL / pkcs5 default
        assert!(limits.scrypt_within(1 << 18, 8, 16)); // 256 MiB, p at cap
        assert!(!limits.scrypt_within(1 << 19, 8, 1)); // 512 MiB
        assert!(!limits.scrypt_within(1 << 14, 8, 17));
        assert!(!limits.scrypt_within(u64::MAX, u16::MAX, 1)); // no overflow
    }
}
