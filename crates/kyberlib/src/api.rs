// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{
    error::KyberLibError,
    kem::*,
    kex::{Decapsulated, Encapsulated, PublicKey, SecretKey},
    params::*,
    CryptoRng, RngCore,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Generate a key pair for Kyber encryption with a provided RNG.
///
/// This function generates a key pair consisting of a public key and a secret key for Kyber encryption.
///
/// # Arguments
///
/// * `rng` - The random number generator implementing the `RngCore` and `CryptoRng` traits.
///
/// # Errors
///
/// Returns a `KyberLibError` if an error occurs during key pair generation.
///
/// ### Example
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// # Ok(())}
/// ```
pub fn keypair<R>(rng: &mut R) -> Result<Keypair, KyberLibError>
where
    R: RngCore + CryptoRng,
{
    let mut public = [0u8; KYBER_PUBLIC_KEY_BYTES];
    let mut secret = [0u8; KYBER_SECRET_KEY_BYTES];
    generate_key_pair(&mut public, &mut secret, rng, None)?;
    let keys = Keypair { public, secret };
    secret.zeroize();
    Ok(keys)
}

/// Verify that given secret and public key matches and put them in
/// the KeyPair structure after zeroize them if asked.
/// ### Example
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// let mut public = keys.public;
/// let mut secret = keys.secret;
/// let _ = keypairfrom(&mut public, &mut secret, &mut rng)?;
/// # Ok(())}
/// ```
pub fn keypairfrom<R>(
    public: &mut [u8; KYBER_PUBLIC_KEY_BYTES],
    secret: &mut [u8; KYBER_SECRET_KEY_BYTES],
    rng: &mut R,
) -> Result<Keypair, KyberLibError>
where
    R: RngCore + CryptoRng,
{
    //Try to encapsulate and decapsulate to verify secret key matches public key
    let (ciphertext, shared_secret) = encapsulate(public, rng)?;
    let expected_shared_secret = decapsulate(&ciphertext, secret)?;
    //If it does match, return a KeyPair
    if expected_shared_secret == shared_secret {
        let public2 = *public;
        let secret2 = *secret;
        let key = Keypair {
            public: public2,
            secret: secret2,
        };
        // Zeroize only the caller-supplied secret slice. Public keys are
        // not sensitive (and zeroizing them would surprise callers who
        // expect their input buffers to be preserved). The in-struct
        // `secret2` is moved into `key`, which zeroizes via `ZeroizeOnDrop`.
        secret.zeroize();
        Ok(key)
    } else {
        //Else return an error
        Err(KyberLibError::InvalidKey)
    }
}

/// Encapsulates a public key and returns the ciphertext to send and the shared secret.
///
/// This function encapsulates a public key and returns the ciphertext and the shared secret.
///
/// # Arguments
///
/// * `pk` - The public key as a slice of bytes.
/// * `rng` - The random number generator implementing the `RngCore` and `CryptoRng` traits.
///
/// # Errors
///
/// Returns a `KyberLibError` if the input sizes are incorrect or if an error occurs during encapsulation.
///
/// ### Example
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// let (ciphertext, shared_secret) = encapsulate(&keys.public, &mut rng)?;
/// # Ok(())}
/// ```
pub fn encapsulate<R>(pk: &[u8], rng: &mut R) -> Encapsulated
where
    R: CryptoRng + RngCore,
{
    if pk.len() != KYBER_PUBLIC_KEY_BYTES {
        return Err(KyberLibError::InvalidInput);
    }
    let mut ct = [0u8; KYBER_CIPHERTEXT_BYTES];
    let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
    encrypt_message(&mut ct, &mut ss, pk, rng, None)?;
    Ok((ct, ss))
}

/// Decapsulates ciphertext with a secret key.
///
/// This function decapsulates ciphertext with a secret key and returns the shared secret.
///
/// # Arguments
///
/// * `ct` - The ciphertext as a slice of bytes.
/// * `sk` - The secret key as a slice of bytes.
///
/// # Errors
///
/// Returns a `KyberLibError` if the input sizes are incorrect or if decapsulation fails.
///
/// ### Example
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// let (ct, ss1) = encapsulate(&keys.public, &mut rng)?;
/// let ss2 = decapsulate(&ct, keys.expose_secret())?;
/// assert_eq!(ss1, ss2);
/// #  Ok(())}
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated {
    if ct.len() != KYBER_CIPHERTEXT_BYTES
        || sk.len() != KYBER_SECRET_KEY_BYTES
    {
        return Err(KyberLibError::InvalidInput);
    }
    let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
    decrypt_message(&mut ss, ct, sk);
    Ok(ss)
}

/// A public/secret keypair for use with Kyber.
///
/// Byte lengths of the keys are determined by the security level chosen.
///
/// # Secret handling
///
/// `Keypair` no longer derives [`Copy`] (since v0.0.7). This is a deliberate
/// footgun fix: a `Copy` secret would defeat [`ZeroizeOnDrop`] by leaving
/// uncleared stack copies behind whenever the value was passed by value.
///
/// [`Zeroize`] and [`ZeroizeOnDrop`] are now derived unconditionally — the
/// `zeroize` Cargo feature is retained as a no-op opt-out and will be removed
/// in a future release. To pass a `Keypair` around, take it by reference
/// (`&Keypair`) or clone it explicitly (`keys.clone()`); the explicit
/// `.clone()` makes secret duplication visible at call sites.
///
/// Phase 3 of the v0.0.7 roadmap (issue #154) splits this further into
/// `EncapsulationKey` (public, `Copy`-safe) and `DecapsulationKey` (private,
/// `!Copy`, `ZeroizeOnDrop`, with a redacted `Debug` impl).
#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Keypair {
    /// The public key.
    pub public: PublicKey,
    /// The secret key.
    pub secret: SecretKey,
}

impl Keypair {
    /// Securely generates a new keypair.
    ///
    /// This function generates a new Kyber key pair and returns it as a `Keypair` struct.
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator implementing the `RngCore` and `CryptoRng` traits.
    ///
    /// ### Example
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// let mut rng = rand::thread_rng();
    /// let keys = Keypair::generate(&mut rng)?;
    /// # let empty_keys = Keypair{
    ///   public: [0u8; KYBER_PUBLIC_KEY_BYTES], secret: [0u8; KYBER_SECRET_KEY_BYTES]
    /// };
    /// # assert!(empty_keys != keys);
    /// # Ok(()) }
    /// ```
    pub fn generate<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Keypair, KyberLibError> {
        keypair(rng)
    }

    /// Explicitly exposes the secret key
    ///```
    /// use kyberlib::*;
    ///
    /// let mut rng = rand::thread_rng();
    /// let keys = Keypair::generate(&mut rng);
    /// let binding = keys.expect("Exposed secret key");
    /// let secret = binding.expose_secret();
    /// assert!(secret.len() == KYBER_SECRET_KEY_BYTES);
    /// assert!(secret.len() != 0);
    /// ```
    pub fn expose_secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Imports a keypair from existing public and secret key arrays.
    ///
    /// This function imports a keypair from existing public and secret key
    /// arrays and returns it as a `Keypair` struct.
    ///
    /// # Arguments
    ///
    /// * `public` - A mutable reference to a `[u8; KYBER_PUBLIC_KEY_BYTES]` array representing the public key.
    /// * `secret` - A mutable reference to a `[u8; KYBER_SECRET_KEY_BYTES]` array representing the secret key.
    /// * `rng` - The random number generator implementing the `RngCore` and `CryptoRng` traits.
    ///
    /// # Secret hygiene
    ///
    /// On success, the caller-supplied `secret` buffer is zeroized in place
    /// (since v0.0.7). Subsequent calls with the same `secret` buffer will
    /// therefore return [`KyberLibError::InvalidKey`]; this is intentional —
    /// the secret has only one valid home, the returned [`Keypair`]. If you
    /// genuinely need a copy, use [`Keypair::clone`] on the returned value.
    ///
    /// # Example
    ///
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// let mut rng = rand::thread_rng();
    /// let keys = keypair(&mut rng)?;
    /// let mut public_key = keys.public;
    /// let mut secret_key = keys.secret;
    /// let imported = Keypair::import(&mut public_key, &mut secret_key, &mut rng)?;
    /// // `secret_key` has been zeroized in place; `imported.secret` is the
    /// // only remaining copy and will be zeroized when `imported` is dropped.
    /// # let _ = imported;
    /// # Ok(()) }
    /// ```
    pub fn import<R: CryptoRng + RngCore>(
        public: &mut [u8; KYBER_PUBLIC_KEY_BYTES],
        secret: &mut [u8; KYBER_SECRET_KEY_BYTES],
        rng: &mut R,
    ) -> Result<Keypair, KyberLibError> {
        keypairfrom(public, secret, rng)
    }
}

struct DummyRng {}

impl CryptoRng for DummyRng {}

impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        panic!()
    }

    fn next_u64(&mut self) -> u64 {
        panic!()
    }

    fn try_fill_bytes(
        &mut self,
        _dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        panic!()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!()
    }
}

/// Deterministically derive a keypair from a seed as specified in draft-schwabe-cfrg-kyber.
///
/// This function deterministically derives a key pair from a seed and returns it as a `Keypair` struct.
///
/// # Arguments
///
/// * `seed` - The seed as a slice of bytes.
///
/// # Errors
///
/// Returns a `KyberLibError` if the seed length is incorrect.
pub fn derive(seed: &[u8]) -> Result<Keypair, KyberLibError> {
    let mut public = [0u8; KYBER_PUBLIC_KEY_BYTES];
    let mut secret = [0u8; KYBER_SECRET_KEY_BYTES];
    let mut _rng = DummyRng {};
    if seed.len() != 64 {
        return Err(KyberLibError::InvalidInput);
    }
    generate_key_pair(
        &mut public,
        &mut secret,
        &mut _rng,
        Some((&seed[..32], &seed[32..])),
    )?;
    Ok(Keypair { public, secret })
}

/// Extracts a public key from a private key.
///
/// This function extracts the public key from a private key.
///
/// # Arguments
///
/// * `sk` - The secret key as a slice of bytes.
///
/// # Returns
///
/// Returns the public key as a `PublicKey`.
pub fn public(sk: &[u8]) -> PublicKey {
    let mut pk = [0u8; KYBER_INDCPA_PUBLIC_KEY_BYTES];
    pk.copy_from_slice(
        &sk[KYBER_INDCPA_SECRET_KEY_BYTES
            ..KYBER_INDCPA_SECRET_KEY_BYTES
                + KYBER_INDCPA_PUBLIC_KEY_BYTES],
    );
    pk
}
