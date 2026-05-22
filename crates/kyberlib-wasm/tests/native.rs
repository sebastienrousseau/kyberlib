//! Native integration tests for the `kyberlib-wasm` Rust surface.
//!
//! These tests run under host `cargo test` — they exercise the
//! `keypair` / `encapsulate` / `decapsulate` Rust functions and the
//! `Keys` / `Kex` typed wrappers without needing a wasm runtime.
//!
//! Why both this file *and* `tests/integration.rs`?
//!
//! * `tests/integration.rs` is gated on `#[cfg(target_arch = "wasm32")]`
//!   and runs via `wasm-pack test` against a real wasm-bindgen
//!   runtime. That's the right place to test JS↔WASM marshalling.
//! * This file runs under native `cargo test` (no wasm toolchain
//!   required) and asserts that the Rust-side API contracts hold —
//!   the byte lengths, the length validation, the round-trip
//!   correctness. This is the kind of coverage that lands in the
//!   workspace coverage report.

use kyberlib::{
    KYBER_CIPHERTEXT_BYTES, KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES, KYBER_SHARED_SECRET_BYTES,
};
use kyberlib_wasm::{decapsulate, encapsulate, keypair, Params};

#[test]
fn params_match_kyberlib_core() {
    assert_eq!(Params::publicKeyBytes(), KYBER_PUBLIC_KEY_BYTES);
    assert_eq!(Params::secretKeyBytes(), KYBER_SECRET_KEY_BYTES);
    assert_eq!(Params::ciphertextBytes(), KYBER_CIPHERTEXT_BYTES);
    assert_eq!(
        Params::sharedSecretBytes(),
        KYBER_SHARED_SECRET_BYTES,
    );
}

#[test]
fn round_trip_matches_kyberlib_byte_shapes() {
    let keys = keypair().expect("keypair generation must succeed");

    let pubkey = keys.pubkey();
    let secret = keys.secret();
    assert_eq!(
        pubkey.len(),
        KYBER_PUBLIC_KEY_BYTES,
        "WASM Keys::pubkey must match kyberlib core byte length"
    );
    assert_eq!(
        secret.len(),
        KYBER_SECRET_KEY_BYTES,
        "WASM Keys::secret must match kyberlib core byte length"
    );

    let exchange = encapsulate(pubkey)
        .expect("encap against own pubkey must succeed");
    let ct = exchange.ciphertext();
    let ss_sender = exchange.sharedSecret();
    assert_eq!(
        ct.len(),
        KYBER_CIPHERTEXT_BYTES,
        "WASM Kex::ciphertext must match kyberlib core byte length"
    );
    assert_eq!(
        ss_sender.len(),
        KYBER_SHARED_SECRET_BYTES,
        "WASM Kex::sharedSecret must be 32 bytes per FIPS 203"
    );

    let recovered = decapsulate(ct, secret)
        .expect("decap must succeed on a freshly-encap'd ciphertext");

    assert_eq!(
        &recovered[..],
        &ss_sender[..],
        "decap must recover the exact shared secret on a \
         well-formed ciphertext"
    );
}

#[test]
fn encapsulate_rejects_wrong_length_public_key() {
    let short = vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1].into_boxed_slice();
    assert!(
        encapsulate(short).is_err(),
        "encap must reject a public key shorter than FIPS 203 §6 spec"
    );

    let long = vec![0u8; KYBER_PUBLIC_KEY_BYTES + 1].into_boxed_slice();
    assert!(
        encapsulate(long).is_err(),
        "encap must reject a public key longer than FIPS 203 §6 spec"
    );
}

#[test]
fn decapsulate_rejects_wrong_length_ciphertext() {
    let keys = keypair().unwrap();
    let bad_ct =
        vec![0u8; KYBER_CIPHERTEXT_BYTES - 1].into_boxed_slice();

    assert!(
        decapsulate(bad_ct, keys.secret()).is_err(),
        "decap must reject a ciphertext shorter than spec"
    );
}

#[test]
fn decapsulate_rejects_wrong_length_secret_key() {
    let keys = keypair().unwrap();
    let exchange = encapsulate(keys.pubkey()).unwrap();
    let bad_sk =
        vec![0u8; KYBER_SECRET_KEY_BYTES - 1].into_boxed_slice();

    assert!(
        decapsulate(exchange.ciphertext(), bad_sk).is_err(),
        "decap must reject a secret key shorter than spec"
    );
}

#[test]
fn decapsulate_implicit_rejection_returns_pseudorandom_secret() {
    // FIPS 203 §6.3 implicit rejection: a length-valid but tampered
    // ciphertext decapsulates to a pseudorandom 32-byte string,
    // never an error. This is the property that defeats Bleichen-
    // bacher-style decapsulation oracles.
    let keys = keypair().unwrap();
    let exchange = encapsulate(keys.pubkey()).unwrap();
    let real_ss = exchange.sharedSecret();

    // Flip a single bit in the middle of the ciphertext.
    let mut tampered = exchange.ciphertext().to_vec();
    tampered[KYBER_CIPHERTEXT_BYTES / 2] ^= 0x01;
    let tampered = tampered.into_boxed_slice();

    let pseudorandom_ss = decapsulate(tampered, keys.secret())
        .expect("implicit rejection must NOT surface an error");

    assert_ne!(
        &pseudorandom_ss[..],
        &real_ss[..],
        "tampered ciphertext must NOT decapsulate to the real \
         shared secret (would be a confidentiality break)"
    );
    assert_eq!(
        pseudorandom_ss.len(),
        KYBER_SHARED_SECRET_BYTES,
        "implicit-rejection output is still 32 bytes"
    );
}

#[test]
fn two_independent_rounds_yield_distinct_secrets() {
    // Sanity check that the RNG plumbing is wired correctly.
    let k1 = keypair().unwrap();
    let k2 = keypair().unwrap();
    assert_ne!(
        &k1.pubkey()[..],
        &k2.pubkey()[..],
        "two independent key pairs must not collide on pubkey \
         (would indicate broken RNG plumbing)"
    );

    let ex1 = encapsulate(k1.pubkey()).unwrap();
    let ex2 = encapsulate(k1.pubkey()).unwrap();
    assert_ne!(
        &ex1.sharedSecret()[..],
        &ex2.sharedSecret()[..],
        "two encaps against the same pk must yield different shared \
         secrets (the `m` value is fresh per call)"
    );
}
