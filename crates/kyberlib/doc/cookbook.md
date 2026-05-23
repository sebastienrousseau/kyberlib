# Cookbook

> Last Updated: 2026-05-22

Copy-pasteable recipes for the most common integration shapes. Each
recipe is a complete, runnable Rust file — no `// ...` elision. The
goal is "find your scenario, paste, edit".

## Recipe index

* [Vanilla KEM round-trip](#vanilla-kem-round-trip)
* [Choosing a parameter set at runtime](#choosing-a-parameter-set-at-runtime)
* [Deterministic keygen from a seed (testing / KAT)](#deterministic-keygen-from-a-seed)
* [Wire serialisation: bytes ⇄ typed wrappers](#wire-serialisation)
* [`no_std` consumer](#no_std-consumer)
* [Mutually authenticated key exchange (Ake)](#mutually-authenticated-key-exchange)
* [Integration with `aead`-style symmetric ciphers](#integration-with-aead-style-symmetric-ciphers)
* [TLS-style hybrid (kyberlib-hybrid)](#tls-style-hybrid)

## Vanilla KEM round-trip

The Rust equivalent of "Hello, world" for ML-KEM.

```rust
use kyberlib::{KemCore, MlKem768};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    let (bob_dk, bob_ek) = MlKem768::generate(&mut rng)?;

    let (ct, ss_alice) = bob_ek.encapsulate(&mut rng)?;

    let ss_bob = bob_dk.decapsulate(&ct);

    assert_eq!(ss_alice, ss_bob);
    println!("32-byte shared secret derived");
    Ok(())
}
```

## Choosing a parameter set at runtime

Use a sealed marker trait and dispatch via match arms.

```rust
use kyberlib::{KemCore, KyberLibError, MlKem1024, MlKem512, MlKem768};

enum Strength {
    Low,    // ML-KEM-512  — NIST category 1
    Medium, // ML-KEM-768  — NIST category 3 (default)
    High,   // ML-KEM-1024 — NIST category 5
}

fn keygen(strength: Strength, rng: &mut impl rand_core::RngCore + rand_core::CryptoRng)
    -> Result<Vec<u8>, KyberLibError>
{
    match strength {
        Strength::Low => {
            let (_, ek) = MlKem512::generate(rng)?;
            Ok(ek.as_bytes().to_vec())
        }
        Strength::Medium => {
            let (_, ek) = MlKem768::generate(rng)?;
            Ok(ek.as_bytes().to_vec())
        }
        Strength::High => {
            let (_, ek) = MlKem1024::generate(rng)?;
            Ok(ek.as_bytes().to_vec())
        }
    }
}
```

## Deterministic keygen from a seed

Useful for KAT harnesses and reproducible test vectors. Uses the
legacy free-function API which accepts an explicit (`d`, `z`) seed
pair per FIPS 203 §6.1.

```rust
use kyberlib::keypair_with_seed; // not yet public — issue #178

// Until #178 lands, the deterministic surface is gated on
// `--cfg KYBER_SECURITY_PARAMETERat` (the ACVP harness path).
// For now use kyberlib::derive(seed) which takes a 64-byte concat.

fn main() -> Result<(), kyberlib::KyberLibError> {
    let seed = [0x42u8; 64];
    let keys = kyberlib::derive(&seed)?;
    assert_eq!(keys.public.len(), 1184);
    Ok(())
}
```

## Wire serialisation

The typed wrappers store bytes verbatim and expose `as_bytes()`.
Wire encoding can be flat byte concatenation — no length prefixes
are needed because the sizes are fixed per parameter set.

```rust
use kyberlib::{KemCore, MlKem768, MlKem768EncapKey};

// Sender side
let (dk, ek) = MlKem768::generate(&mut rand::thread_rng())?;
let wire: &[u8; 1184] = ek.as_bytes();
let to_send: Vec<u8> = wire.to_vec();

// Receiver side
let bytes: &[u8] = &to_send;
let ek_recv = MlKem768EncapKey::try_from_slice(bytes)
    .map_err(|_| "wire-format error")?;
# Ok::<_, kyberlib::KyberLibError>(())
```

For binary protocols like CBOR / PostCard, the byte arrays
serialise as fixed-length byte strings. No `#[serde]` derives needed
on the kyberlib side — wrap in your own struct:

```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct WireMessage {
    pk: [u8; 1184],   // matches MlKem768::PUBLIC_KEY_BYTES
    ct: [u8; 1088],   // matches MlKem768::CIPHERTEXT_BYTES
}
```

## `no_std` consumer

kyberlib works on `no_std` with the default features + `--no-default-features`.

```toml
[dependencies]
kyberlib = { version = "0.0.7", default-features = false, features = ["kyber768"] }
```

```rust
#![no_std]

use kyberlib::{KemCore, MlKem768};
use rand_core::{CryptoRng, RngCore};

fn handshake<R: RngCore + CryptoRng>(rng: &mut R)
    -> Result<(), kyberlib::KyberLibError>
{
    let (dk, ek) = MlKem768::generate(rng)?;
    let (ct, ss_a) = ek.encapsulate(rng)?;
    let ss_b = dk.decapsulate(&ct);
    debug_assert_eq!(ss_a, ss_b);
    Ok(())
}
```

Stack usage per handshake is ~14 KB worst case (ML-KEM-1024); see
[`architecture.md`](./architecture.md#the-const-generic-pipeline-130b)
for the breakdown.

## Mutually authenticated key exchange

The [`Ake`] wrapper adds mutual authentication on top of the bare KEM.
Three messages: client → server → client; both parties end with the
same 32-byte shared secret.

```rust
use kyberlib::{keypair, Ake};

fn main() -> Result<(), kyberlib::KyberLibError> {
    let mut rng = rand::thread_rng();

    let mut alice = Ake::new();
    let mut bob = Ake::new();

    let alice_keys = keypair(&mut rng)?;
    let bob_keys = keypair(&mut rng)?;

    // 1. Alice → Bob
    let client_init = alice.client_init(&bob_keys.public, &mut rng)?;

    // 2. Bob → Alice
    let server_send = bob.server_receive(
        client_init,
        &alice_keys.public,
        &bob_keys.secret,
        &mut rng,
    )?;

    // 3. Alice finalises
    alice.client_confirm(server_send, &alice_keys.secret)?;

    assert_eq!(alice.shared_secret, bob.shared_secret);
    Ok(())
}
```

See [`kex` module docs](https://docs.rs/kyberlib/latest/kyberlib/kex/index.html)
for the [`Uake`] (unilaterally authenticated) variant.

## Integration with `aead`-style symmetric ciphers

ML-KEM produces a 32-byte shared secret. Plug it into ChaCha20-Poly1305
or AES-256-GCM as the key:

```rust
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use kyberlib::{KemCore, MlKem768};

fn encrypt_for(recipient_ek: &kyberlib::MlKem768EncapKey, plaintext: &[u8])
    -> Result<(Vec<u8>, kyberlib::MlKem768Ciphertext), Box<dyn std::error::Error>>
{
    let mut rng = OsRng;
    let (ct, ss) = recipient_ek.encapsulate(&mut rng)?;

    let cipher = ChaCha20Poly1305::new(ss.as_bytes().into());
    let nonce = Nonce::default(); // PRODUCTION: derive per-message
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    Ok((ciphertext, ct))
}
```

Note: this is a one-shot exchange. For long-running sessions, derive
a session key via HKDF on the KEM output rather than using it
directly as a cipher key.

## TLS-style hybrid

The [`kyberlib-hybrid`](https://docs.rs/kyberlib-hybrid) crate
combines ML-KEM with classical X25519 per draft-ietf-tls-ecdhe-mlkem-04.
This is the construction the IETF TLS WG settled on for post-quantum
TLS 1.3.

See [`crates/kyberlib-hybrid/doc/architecture.md`](../../kyberlib-hybrid/doc/architecture.md).

[`Ake`]: https://docs.rs/kyberlib/latest/kyberlib/struct.Ake.html
[`Uake`]: https://docs.rs/kyberlib/latest/kyberlib/struct.Uake.html
