//! `#![no_std]`-compatible ML-KEM-768 round-trip.
//!
//! `kyberlib` runs on embedded targets that don't have `std`. The
//! safe core only needs `alloc` (for the rejection-sampler `Vec`
//! buffers) and a caller-supplied RNG that implements
//! `rand_core::{CryptoRng, RngCore}`. On bare metal you'd typically
//! plug a hardware TRNG wrapper (e.g. `embedded-hal`'s `rand_core`
//! impl over an STM32 / nRF / RP2040 peripheral); this example uses
//! a small ChaCha20-based RNG seeded from a constant just to keep
//! the demo self-contained.
//!
//! ## Why this example uses `std` for the binary
//!
//! `cargo run --example` requires a `main` symbol, which in turn
//! requires `std`. To keep the example runnable from this workspace,
//! the binary itself is `std`-flavoured — but every call into
//! `kyberlib` goes through the no_std API surface. The `handshake`
//! function below is generic over `R: CryptoRng + RngCore` and would
//! compile unchanged on a `#![no_std]` crate.
//!
//! Run with: `cargo run --example no_std_demo`.

use kyberlib::{KemCore, KyberLibError, MlKem768};
use rand_core::{CryptoRng, RngCore, SeedableRng};

/// The whole kyberlib surface used by an embedded consumer.
///
/// This function does not import anything from `std::*`. The only
/// trait bounds are `rand_core::CryptoRng + RngCore` — the same
/// shape an embedded TRNG driver exposes.
fn handshake<R: CryptoRng + RngCore>(
    rng: &mut R,
) -> Result<(), KyberLibError> {
    // (1) Receiver generates a key pair. Both halves are heap-
    //     allocated under the hood (the `alloc` requirement); on
    //     a no_std target the global allocator is whatever the
    //     `extern crate alloc;` line resolves to.
    let (dk, ek) = MlKem768::generate(rng)?;

    // (2) Sender encapsulates a fresh shared secret against the
    //     receiver's public key.
    let (ct, ss_sender) = ek.encapsulate(rng)?;

    // (3) Receiver decapsulates the ciphertext.
    let ss_receiver = dk.decapsulate(&ct);

    // Both sides must agree.
    debug_assert_eq!(ss_sender, ss_receiver);

    Ok(())
}

fn main() -> Result<(), KyberLibError> {
    // Construct a deterministic RNG so this example is reproducible.
    // In production embedded code, swap this for your hardware TRNG.
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0x37u8; 32]);

    handshake(&mut rng)?;

    println!(
        "no_std-style ML-KEM-768 round-trip completed; the \
         `handshake<R: CryptoRng + RngCore>` function above is the \
         single-file shape an embedded consumer would use."
    );

    Ok(())
}
