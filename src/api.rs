use crate::{
    error::KyberLibError,
    kem::*,
    kex::{Decapsulated, Encapsulated, PublicKey, SecretKey},
    params::*,
    CryptoRng, RngCore,
};

/// Keypair generation with a provided RNG.
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
    Ok(Keypair { public, secret })
}

/// Encapsulates a public key returning the ciphertext to send
/// and the shared secret
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

/// Decapsulates ciphertext with a secret key, the result will contain
/// a KyberLibError if decapsulation fails
///
/// ### Example
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
/// let keys = keypair(&mut rng)?;
/// let (ct, ss1) = encapsulate(&keys.public, &mut rng)?;
/// let ss2 = decapsulate(&ct, &keys.secret)?;
/// assert_eq!(ss1, ss2);
/// #  Ok(())}
/// ```
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Decapsulated {
    if ct.len() != KYBER_CIPHERTEXT_BYTES || sk.len() != KYBER_SECRET_KEY_BYTES {
        return Err(KyberLibError::InvalidInput);
    }
    let mut ss = [0u8; KYBER_SHARED_SECRET_BYTES];
    decrypt_message(&mut ss, ct, sk);
    Ok(ss)
}

/// A public/secret keypair for use with Kyber.
///
/// Byte lengths of the keys are determined by the security level chosen.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Keypair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl Keypair {
    /// Securely generates a new keypair`
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
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Keypair, KyberLibError> {
        keypair(rng)
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
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
        panic!()
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        panic!()
    }
}

/// Deterministically derive a keypair from a seed as specified
/// in draft-schwabe-cfrg-kyber.
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

/// Extracts public key from private key.
pub fn public(sk: &[u8]) -> PublicKey {
    let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
    pk.copy_from_slice(
        &sk[KYBER_INDCPA_SECRETKEYBYTES..KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES],
    );
    pk
}
