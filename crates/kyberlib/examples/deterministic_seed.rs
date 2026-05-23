//! Deterministic ML-KEM-768 keygen from a 64-byte seed.
//!
//! Every call to `kyberlib::derive(&seed)` with the same 64 bytes
//! produces a byte-identical `Keypair`. That property is what lets
//! the NIST ACVP harness (`tests/test_acvp.rs`) reproduce NIST's
//! expected outputs from the published `(d, z)` inputs, and what lets
//! consumers reproduce test vectors across hosts.
//!
//! ## Production-use warning
//!
//! Deterministic keygen is for **test harnesses and KAT
//! reproduction only**. In production, always source the seed from a
//! cryptographically secure RNG (`OsRng`, hardware TRNG) — passing a
//! constant or predictable seed produces a world-knowable keypair
//! that any attacker can re-derive.
//!
//! ## How the bytes map to FIPS 203
//!
//! FIPS 203 §5.1 takes two 32-byte values:
//!
//! * `d` — the encapsulation-side seed,
//! * `z` — the implicit-rejection seed (used in §6.3).
//!
//! `kyberlib::derive` accepts a 64-byte slice and splits it as
//! `(&seed[..32], &seed[32..])` — i.e. `d` first, then `z`.
//!
//! Run with: `cargo run --example deterministic_seed`.

use kyberlib::{derive, KyberLibError};

fn main() -> Result<(), KyberLibError> {
    // A fixed 64-byte test seed. In production code, you would
    // source these bytes from a cryptographically secure RNG.
    let seed = [0x42u8; 64];

    // Derive a keypair from the seed.
    let keys_a = derive(&seed)?;
    assert_eq!(
        keys_a.public.len(),
        1184,
        "ML-KEM-768 EncapKey length per FIPS 203"
    );
    assert_eq!(
        keys_a.secret.len(),
        2400,
        "ML-KEM-768 DecapKey length per FIPS 203"
    );

    // Same seed → byte-identical keypair. This is the
    // reproducibility property the ACVP harness relies on.
    let keys_b = derive(&seed)?;
    assert_eq!(keys_a.public, keys_b.public);
    assert_eq!(keys_a.secret, keys_b.secret);

    // Reject seeds of the wrong length — derive returns
    // `KyberLibError::InvalidInput` rather than padding or panicking.
    assert!(derive(&[0u8; 63]).is_err(), "63-byte seed must fail");
    assert!(derive(&[0u8; 65]).is_err(), "65-byte seed must fail");

    println!(
        "Deterministic ML-KEM-768 keygen reproduced from a fixed \
         seed: pk={} B, sk={} B (byte-identical across both calls).",
        keys_a.public.len(),
        keys_a.secret.len(),
    );

    Ok(())
}
