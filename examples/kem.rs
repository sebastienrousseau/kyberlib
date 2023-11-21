//! Example demonstrating the usage of KyberLib for key exchange.
//!
//! This example shows how Alice and Bob can use KyberLib to perform a key exchange
//! and establish a shared secret for secure communication.
//!
//! # Usage
//!
//! 1. Ensure you have the `kyberlib` crate installed and added as a dependency in your `Cargo.toml`.
//! 2. Build and run this example with `cargo run`.
//!
//! # Note
//!
//! This example assumes you have the necessary dependencies and configurations in your project.
//!
//! For more information on KyberLib and usage details, please refer to the documentation.
//!
//! # License
//!
//! This example is licensed under either of the following, at your choice:
//!
//! - Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
//! - MIT License (LICENSE-MIT or http://opensource.org/licenses/MIT)

use kyberlib::*;

fn main() -> Result<(), KyberLibError> {
    let mut rng = rand::thread_rng();

    // Alice generates a keypair
    let alice_keys = keypair(&mut rng)?;

    // Bob encapsulates a shared secret
    let (ciphertext, shared_secret_bob) = encapsulate(&alice_keys.public, &mut rng)?;

    // Alice decapsulates the shared secret
    let shared_secret_alice = decapsulate(&ciphertext, &alice_keys.secret)?;

    // Both can now communicate symmetrically
    assert_eq!(shared_secret_alice, shared_secret_bob);
    Ok(())
}
