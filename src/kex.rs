use crate::{kem::*, params::*, symmetric::kdf, KyberLibError};
use rand_core::{CryptoRng, RngCore};

/// Unilateral Key Exchange Initiation Byte Length
pub const UAKE_INIT_BYTES: usize = KYBER_PUBLIC_KEY_BYTES + KYBER_CIPHERTEXT_BYTES;
/// Unilateral Key Exchange Response Byte Length
pub const UAKE_RESPONSE_BYTES: usize = KYBER_CIPHERTEXT_BYTES;
/// Mutual Key Exchange Initiation Byte Length
pub const AKE_INIT_BYTES: usize = KYBER_PUBLIC_KEY_BYTES + KYBER_CIPHERTEXT_BYTES;
/// Mutual Key Exchange Response Byte Length
pub const AKE_RESPONSE_BYTES: usize = 2 * KYBER_CIPHERTEXT_BYTES;

/// Result of encapsulating a public key which includes the ciphertext and shared secret
pub type Encapsulated = Result<([u8; KYBER_CIPHERTEXT_BYTES], [u8; KYBER_SHARED_SECRET_BYTES]), KyberLibError>;
/// Decapsulated ciphertext
pub type Decapsulated = Result<[u8; KYBER_SHARED_SECRET_BYTES], KyberLibError>;
/// Kyber public key
pub type PublicKey = [u8; KYBER_PUBLIC_KEY_BYTES];
/// Kyber secret key
pub type SecretKey = [u8; KYBER_SECRET_KEY_BYTES];
/// Kyber Shared Secret
pub type SharedSecret = [u8; KYBER_SHARED_SECRET_BYTES];
/// Bytes to send when initiating a unilateral key exchange
pub type UakeSendInit = [u8; UAKE_INIT_BYTES];
/// Bytes to send when responding to a unilateral key exchange
pub type UakeSendResponse = [u8; UAKE_RESPONSE_BYTES];
/// Bytes to send when initiating a mutual key exchange
pub type AkeSendInit = [u8; AKE_INIT_BYTES];
/// Bytes to send when responding to a mutual key exchange
pub type AkeSendResponse = [u8; AKE_RESPONSE_BYTES];

// Ephemeral keys
type TempKey = [u8; KYBER_SHARED_SECRET_BYTES];
type Eska = [u8; KYBER_SECRET_KEY_BYTES];

/// Represents unilaterally authenticated key exchange between two parties.
///
/// # Example:
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
///
/// let mut alice = Uake::new();
/// let mut bob = Uake::new();
/// let bob_keys = keypair(&mut rng)?;
///
/// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
/// let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
/// let client_confirm = alice.client_confirm(server_send)?;
///
/// assert_eq!(alice.shared_secret, bob.shared_secret);
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Uake {
    /// The resulting shared secret from a key exchange
    pub shared_secret: SharedSecret,
    /// Sent when initiating a key exchange
    send_a: UakeSendInit,
    /// Response to a key exchange initiation
    send_b: UakeSendResponse,
    // Ephemeral keys
    temp_key: TempKey,
    eska: Eska,
}

impl Default for Uake {
    fn default() -> Self {
        Uake {
            shared_secret: [0u8; KYBER_SHARED_SECRET_BYTES],
            send_a: [0u8; UAKE_INIT_BYTES],
            send_b: [0u8; UAKE_RESPONSE_BYTES],
            temp_key: [0u8; KYBER_SHARED_SECRET_BYTES],
            eska: [0u8; KYBER_SECRET_KEY_BYTES],
        }
    }
}

impl Uake {
    /// Creates a new UAKE struct.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::Uake;
    /// let mut kex = Uake::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Initiates a Unilaterally Authenticated Key Exchange.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// let mut rng = rand::thread_rng();
    /// let mut alice = Uake::new();
    /// let bob_keys = keypair(&mut rng)?;
    /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// # Ok(()) }
    /// ```
    pub fn client_init<R>(
        &mut self,
        pubkey: &PublicKey,
        rng: &mut R,
    ) -> Result<UakeSendInit, KyberLibError>
    where
        R: CryptoRng + RngCore,
    {
        uake_init_a(
            &mut self.send_a,
            &mut self.temp_key,
            &mut self.eska,
            pubkey,
            rng,
        )?;
        Ok(self.send_a)
    }

    /// Handles the output of a `client_init()` request.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// # let mut rng = rand::thread_rng();
    /// let mut alice = Uake::new();
    /// let mut bob = Uake::new();
    /// let mut bob_keys = keypair(&mut rng)?;
    /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
    /// # Ok(()) }
    pub fn server_receive<R>(
        &mut self,
        send_a: UakeSendInit,
        secretkey: &SecretKey,
        rng: &mut R,
    ) -> Result<UakeSendResponse, KyberLibError>
    where
        R: CryptoRng + RngCore,
    {
        uake_shared_b(
            &mut self.send_b,
            &mut self.shared_secret,
            &send_a,
            secretkey,
            rng,
        )?;
        Ok(self.send_b)
    }

    /// Decapsulates and authenticates the shared secret from the output of
    /// `server_receive()`.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// # let mut rng = rand::thread_rng();
    /// # let mut alice = Uake::new();
    /// # let mut bob = Uake::new();
    /// # let bob_keys = keypair(&mut rng)?;
    /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// let server_send = bob.server_receive(client_init, &bob_keys.secret, &mut rng)?;
    /// let client_confirm = alice.client_confirm(server_send)?;
    /// assert_eq!(alice.shared_secret, bob.shared_secret);
    /// # Ok(()) }
    pub fn client_confirm(&mut self, send_b: UakeSendResponse) -> Result<(), KyberLibError> {
        uake_shared_a(&mut self.shared_secret, &send_b, &self.temp_key, &self.eska)?;
        Ok(())
    }
}

/// Represents mutually authenticated key exchange between two parties.
///
/// # Example:
/// ```
/// # use kyberlib::*;
/// # fn main() -> Result<(), KyberLibError> {
/// let mut rng = rand::thread_rng();
///
/// let mut alice = Ake::new();
/// let mut bob = Ake::new();
///
/// let alice_keys = keypair(&mut rng)?;
/// let bob_keys = keypair(&mut rng)?;
///
/// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
/// let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
/// let client_confirm = alice.client_confirm(server_send, &alice_keys.secret)?;
///
/// assert_eq!(alice.shared_secret, bob.shared_secret);
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ake {
    /// The resulting shared secret from a key exchange
    pub shared_secret: SharedSecret,
    /// Sent when initiating a key exchange
    send_a: AkeSendInit,
    /// Response to a key exchange initiation
    send_b: AkeSendResponse,
    // Ephemeral keys
    temp_key: TempKey,
    eska: Eska,
}

impl Default for Ake {
    fn default() -> Self {
        Ake {
            shared_secret: [0u8; KYBER_SHARED_SECRET_BYTES],
            send_a: [0u8; AKE_INIT_BYTES],
            send_b: [0u8; AKE_RESPONSE_BYTES],
            temp_key: [0u8; KYBER_SHARED_SECRET_BYTES],
            eska: [0u8; KYBER_SECRET_KEY_BYTES],
        }
    }
}

impl Ake {
    /// Builds a new AKE struct.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::Ake;
    /// let mut kex = Ake::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Initiates a Mutually Authenticated Key Exchange.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// let mut rng = rand::thread_rng();
    /// let mut alice = Ake::new();
    /// let bob_keys = keypair(&mut rng)?;
    /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// # Ok(()) }
    /// ```
    pub fn client_init<R>(
        &mut self,
        pubkey: &PublicKey,
        rng: &mut R,
    ) -> Result<AkeSendInit, KyberLibError>
    where
        R: CryptoRng + RngCore,
    {
        ake_init_a(
            &mut self.send_a,
            &mut self.temp_key,
            &mut self.eska,
            pubkey,
            rng,
        )?;
        Ok(self.send_a)
    }

    /// Handles and authenticates the output of a `client_init()` request.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// # let mut rng = rand::thread_rng();
    /// let mut alice = Ake::new();
    /// let mut bob = Ake::new();
    /// let alice_keys = keypair(&mut rng)?;
    /// let bob_keys = keypair(&mut rng)?;
    /// let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
    /// # Ok(()) }
    pub fn server_receive<R>(
        &mut self,
        ake_send_a: AkeSendInit,
        pubkey: &PublicKey,
        secretkey: &SecretKey,
        rng: &mut R,
    ) -> Result<AkeSendResponse, KyberLibError>
    where
        R: CryptoRng + RngCore,
    {
        ake_shared_b(
            &mut self.send_b,
            &mut self.shared_secret,
            &ake_send_a,
            secretkey,
            pubkey,
            rng,
        )?;
        Ok(self.send_b)
    }

    /// Decapsulates and authenticates the shared secret from the output of
    /// `server_receive()`.
    ///
    /// # Example:
    /// ```
    /// # use kyberlib::*;
    /// # fn main() -> Result<(), KyberLibError> {
    /// # let mut rng = rand::thread_rng();
    /// # let mut alice = Ake::new();
    /// # let mut bob = Ake::new();
    /// # let alice_keys = keypair(&mut rng)?;
    /// # let bob_keys = keypair(&mut rng)?;
    /// # let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
    /// let server_send = bob.server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)?;
    /// let client_confirm = alice.client_confirm(server_send, &alice_keys.secret);
    /// assert_eq!(alice.shared_secret, bob.shared_secret);
    /// # Ok(()) }
    pub fn client_confirm(
        &mut self,
        send_b: AkeSendResponse,
        secretkey: &SecretKey,
    ) -> Result<(), KyberLibError> {
        ake_shared_a(
            &mut self.shared_secret,
            &send_b,
            &self.temp_key,
            &self.eska,
            secretkey,
        )?;
        Ok(())
    }
}

// Unilaterally Authenticated Key Exchange initiation
fn uake_init_a<R>(
    send: &mut [u8],
    tk: &mut [u8],
    sk: &mut [u8],
    pkb: &[u8],
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: CryptoRng + RngCore,
{
    generate_key_pair(send, sk, rng, None)?;
    encrypt_message(&mut send[KYBER_PUBLIC_KEY_BYTES..], tk, pkb, rng, None)?;
    Ok(())
}

// Unilaterally authenticated key exchange computation by Bob
fn uake_shared_b<R>(
    send: &mut [u8],
    k: &mut [u8],
    recv: &[u8],
    skb: &[u8],
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: CryptoRng + RngCore,
{
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    encrypt_message(send, &mut buf, recv, rng, None)?;
    decrypt_message(
        &mut buf[KYBER_SYM_BYTES..],
        &recv[KYBER_PUBLIC_KEY_BYTES..],
        skb,
    );
    kdf(k, &buf, 2 * KYBER_SYM_BYTES);
    Ok(())
}

// Unilaterally authenticated key exchange computation by Alice
fn uake_shared_a(k: &mut [u8], recv: &[u8], tk: &[u8], sk: &[u8]) -> Result<(), KyberLibError> {
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    decrypt_message(&mut buf, recv, sk);
    buf[KYBER_SYM_BYTES..].copy_from_slice(tk);
    kdf(k, &buf, 2 * KYBER_SYM_BYTES);
    Ok(())
}

// Authenticated key exchange initiation by Alice
fn ake_init_a<R>(
    send: &mut [u8],
    tk: &mut [u8],
    sk: &mut [u8],
    pkb: &[u8],
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: CryptoRng + RngCore,
{
    generate_key_pair(send, sk, rng, None)?;
    encrypt_message(&mut send[KYBER_PUBLIC_KEY_BYTES..], tk, pkb, rng, None)?;
    Ok(())
}

// Mutually authenticated key exchange computation by Bob
fn ake_shared_b<R>(
    send: &mut [u8],
    k: &mut [u8],
    recv: &[u8],
    skb: &[u8],
    pka: &[u8],
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: CryptoRng + RngCore,
{
    let mut buf = [0u8; 3 * KYBER_SYM_BYTES];
    encrypt_message(send, &mut buf, recv, rng, None)?;
    encrypt_message(
        &mut send[KYBER_CIPHERTEXT_BYTES..],
        &mut buf[KYBER_SYM_BYTES..],
        pka,
        rng,
        None,
    )?;
    decrypt_message(
        &mut buf[2 * KYBER_SYM_BYTES..],
        &recv[KYBER_PUBLIC_KEY_BYTES..],
        skb,
    );
    kdf(k, &buf, 3 * KYBER_SYM_BYTES);
    Ok(())
}

// Mutually authenticated key exchange computation by Alice
fn ake_shared_a(
    k: &mut [u8],
    recv: &[u8],
    tk: &[u8],
    sk: &[u8],
    ska: &[u8],
) -> Result<(), KyberLibError> {
    let mut buf = [0u8; 3 * KYBER_SYM_BYTES];
    decrypt_message(&mut buf, recv, sk);
    decrypt_message(
        &mut buf[KYBER_SYM_BYTES..],
        &recv[KYBER_CIPHERTEXT_BYTES..],
        ska,
    );
    buf[2 * KYBER_SYM_BYTES..].copy_from_slice(tk);
    kdf(k, &buf, 3 * KYBER_SYM_BYTES);
    Ok(())
}
