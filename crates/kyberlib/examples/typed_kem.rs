//! Typed `KemCore` ML-KEM-768 round-trip — the v0.0.7-preferred API.
//!
//! Shows how Alice and Bob establish a 32-byte shared secret using
//! `kyberlib`'s typed-state surface. Unlike the legacy `keypair` /
//! `encapsulate` / `decapsulate` free functions (see `examples/kem.rs`),
//! this example uses `MlKem768::generate` and the per-key methods on
//! the resulting `MlKem768DecapKey` / `MlKem768EncapKey`.
//!
//! The typed surface buys you three concrete security properties:
//!
//! 1. **Compile-time secret-hygiene.** `MlKem768DecapKey` is `!Copy`
//!    and `ZeroizeOnDrop`. The Rust compiler refuses an `=`
//!    assignment that would silently duplicate the key, and the
//!    secret bytes are overwritten the moment the key value goes
//!    out of scope.
//! 2. **Redacted `Debug`.** `println!("{:?}", dk)` cannot leak the
//!    bytes — the `Debug` impl prints `[REDACTED N bytes]` instead.
//! 3. **No `Result` on `decapsulate`.** FIPS 203 §6.3 implicit
//!    rejection means decap never errors for a length-valid
//!    ciphertext — it returns a pseudorandom shared secret instead,
//!    making side-channel exploits much harder.
//!
//! Run with: `cargo run --example typed_kem`.

use kyberlib::{KemCore, KyberLibError, MlKem768};

fn main() -> Result<(), KyberLibError> {
    let mut rng = rand::thread_rng();

    // (1) Bob (the receiver) generates a key pair. `bob_dk` is the
    //     decapsulation key — keep it secret. `bob_ek` is the
    //     encapsulation key — share it with Alice over any channel.
    let (bob_dk, bob_ek) = MlKem768::generate(&mut rng)?;

    // The encapsulation key's bytes are what go on the wire (1184 B
    // for ML-KEM-768). Use `ek.as_bytes()` to serialise.
    let _wire_bytes: &[u8; 1184] = bob_ek.as_bytes();

    // (2) Alice (the sender) encapsulates a fresh shared secret
    //     against Bob's public key. She gets back the ciphertext
    //     (1088 B for ML-KEM-768) plus her copy of the shared
    //     secret.
    let (ciphertext, ss_alice) = bob_ek.encapsulate(&mut rng)?;

    // (3) Alice sends `ciphertext.as_bytes()` to Bob. Bob recovers
    //     the same 32-byte shared secret by decapsulating with his
    //     secret key.
    let ss_bob = bob_dk.decapsulate(&ciphertext);

    // Both sides now hold an identical 32-byte symmetric key,
    // suitable for feeding into a symmetric AEAD (ChaCha20-Poly1305,
    // AES-GCM) for the actual data channel.
    assert_eq!(
        ss_alice, ss_bob,
        "shared secrets must match on both sides"
    );

    println!(
        "ML-KEM-768 typed round-trip: 32-byte shared secret \
         established (ek={} B, ct={} B).",
        bob_ek.as_bytes().len(),
        ciphertext.as_bytes().len(),
    );

    Ok(())
}
