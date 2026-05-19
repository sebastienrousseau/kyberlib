//! Example demonstrating the usage of KyberLib for authenticated key exchange (AKE).
//!
//! This example shows how Alice and Bob can use KyberLib to perform an authenticated key exchange
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

    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng)?;
    let bob_keys = keypair(&mut rng)?;

    // Alice initiates key exchange with Bob
    let client_send = alice.client_init(&bob_keys.public, &mut rng)?;

    // Bob receives the request and authenticates Alice, sends
    // encapsulated shared secret back
    let server_send = bob.server_receive(
        client_send,
        &alice_keys.public,
        &bob_keys.secret,
        &mut rng,
    )?;

    // Alice authenticates and decapsulates
    alice.client_confirm(server_send, &alice_keys.secret)?;

    // Both structs now have the shared secret
    assert_eq!(alice.shared_secret, bob.shared_secret);

    Ok(())
}
