// Copyright © 2023 KyberLib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `KyberLib` 🦀
//!
//! `KyberLib` is a robust Rust library designed for CRYSTALS-Kyber Post-Quantum Cryptography, offering strong security guarantees. This library is compatible with `no_std`, making it suitable for embedded devices, and it avoids memory allocations. Additionally, it contains reference implementations with no unsafe code and provides an optimized AVX2 version by default on x86_64 platforms. You can also compile it to WebAssembly (WASM) using wasm-bindgen.
//!
//! [![KyberLib Logo](https://kura.pro/kyberlib/images/banners/banner-kyberlib.svg)](https://kyberlib.com "A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography")
//!
//! ## Features
//!
//! `KyberLib` offers various features to customize its behavior and security level:
//!
//! | Feature   | Description                                                                                                                                                                |
//! |-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
//! | `kyber512`  | Enables Kyber512 mode, providing a security level roughly equivalent to AES-128.                                                                                                |
//! | `kyber1024` | Enables Kyber1024 mode, offering a security level roughly equivalent to AES-256.                   |
//! | `90s`       | Activates 90's mode, which uses SHA2 and AES-CTR as a replacement for SHAKE. This may provide hardware speedups on certain architectures.                                                           |
//! | `avx2`      | On x86_64 platforms, enables the optimized AVX2 version. This flag causes a compile error on other architectures. |
//! | `wasm`      | Enables support for compiling to WASM targets. |
//! | `nasm`      | Uses Netwide Assembler (NASM) AVX2 code instead of GNU Assembler (GAS) for portability. Requires a NASM compiler: <https://www.nasm.us/> |
//! | `zeroize`   | Automatically zeroes out key exchange structs on drop using the [zeroize](https://docs.rs/zeroize/latest/zeroize/) crate |
//! | `std`       | Enables the standard library (std). |
//!
//! ## Usage
//!
//! To optimize for x86 platforms, enable the `avx2` feature and set the following RUSTFLAGS:
//!
//! ```shell
//! export RUSTFLAGS="-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"
//! ```
//!
//! Import the library into your Rust project as follows:
//!
//! ```rust
//! use kyberlib::*;
//! ```
//!
//! ### Key Encapsulation
//!
//! Generate key pairs and encapsulate a shared secret between two parties:
//!
//! ```rust
//! # use kyberlib::*;
//! # fn main() -> Result<(), KyberLibError> {
//! # let mut rng = rand::thread_rng();
//!
//! // Generate Keypair for Bob
//! let keys_bob = keypair(&mut rng)?;
//!
//! // Alice encapsulates a shared secret using Bob's public key
//! let (ciphertext, shared_secret_alice) = encapsulate(&keys_bob.public, &mut rng)?;
//!
//! // Bob decapsulates the shared secret using the ciphertext sent by Alice
//! let shared_secret_bob = decapsulate(&ciphertext, &keys_bob.secret)?;
//!
//! // Verify that both parties share the same secret
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! # Ok(()) }
//! ```
//!
//! ### Unilaterally Authenticated Key Exchange
//!
//! Perform a unilaterally authenticated key exchange between two parties:
//!
//! ```rust
//! # use kyberlib::*;
//! # fn main() -> Result<(), KyberLibError> {
//! let mut rng = rand::thread_rng();
//!
//! // Initialize the key exchange structs for Alice and Bob
//! let mut alice = Uake::new();
//! let mut bob = Uake::new();
//!
//! // Generate Keypairs for Alice and Bob
//! let alice_keys = keypair(&mut rng)?;
//! let bob_keys = keypair(&mut rng)?;
//!
//! // Alice initiates the key exchange
//! let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
//!
//! // Bob authenticates and responds
//! let server_send = bob.server_receive(
//!   client_init, &bob_keys.secret, &mut rng
//! )?;
//!
//! // Alice confirms the server response and retrieves the shared secret
//! alice.client_confirm(server_send)?;
//!
//! // Both Alice and Bob now have the same shared secret
//! assert_eq!(alice.shared_secret, bob.shared_secret);
//! # Ok(()) }
//! ```
//!
//! ### Mutually Authenticated Key Exchange
//!
//! Perform a mutually authenticated key exchange between two parties:
//!
//! ```rust
//! # use kyberlib::*;
//! # fn main() -> Result<(), KyberLibError> {
//! # let mut rng = rand::thread_rng();
//! let mut alice = Ake::new();
//! let mut bob = Ake::new();
//!
//! let alice_keys = keypair(&mut rng)?;
//! let bob_keys = keypair(&mut rng)?;
//!
//! let client_init = alice.client_init(&bob_keys.public, &mut rng)?;
//!
//! let server_send = bob.server_receive(
//!   client_init, &alice_keys.public, &bob_keys.secret, &mut rng
//! )?;
//!
//! alice.client_confirm(server_send, &alice_keys.secret)?;
//!
//! assert_eq!(alice.shared_secret, bob.shared_secret);
//! # Ok(()) }
//! ```
//!
//! ## Errors
//!
//! The [KyberLibError](enum.KyberLibError.html) enum handles errors with two variants:
//!
//! - **InvalidInput**: Occurs when one or more byte inputs to a function are incorrectly sized. This typically happens when two parties use different security levels while attempting to negotiate a key exchange.
//! - **Decapsulation**: This error indicates that the ciphertext could not be authenticated, and the shared secret was not successfully decapsulated.
//!
#![deny(dead_code)]
#![deny(missing_debug_implementations)]
#![forbid(unsafe_code)]
#![warn(unreachable_pub)]
#![doc(
    html_favicon_url = "https://kura.pro/kyberlib/images/favicon.ico",
    html_logo_url = "https://kura.pro/kyberlib/images/logos/kyberlib.svg",
    html_root_url = "https://docs.rs/kyberlib"
)]
#![crate_name = "kyberlib"]
#![crate_type = "lib"]
#![allow(clippy::many_single_char_names)]
#![no_std]

// Prevent usage of mutually exclusive features
#[cfg(all(feature = "kyber1024", feature = "kyber512"))]
compile_error!("Only one security level can be specified");

#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
mod avx2;
#[cfg(all(target_arch = "x86_64", feature = "avx2"))]
use avx2::*;

#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
mod reference;
#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
use reference::*;

#[cfg(any(not(target_arch = "x86_64"), not(feature = "avx2")))]
#[cfg(feature = "hazmat")]
use reference::indcpa;

#[cfg(feature = "wasm")]
/// WebAssembly bindings for the KyberLib library.
pub mod wasm;

/// API for the KyberLib library.
pub mod api;
/// Error types for the KyberLib library.
pub mod error;
/// Key encapsulation module for the KyberLib library.
pub mod kem;
/// Key exchange structs for the KyberLib library.
pub mod kex;
/// Logging utilities for debugging
pub mod loggers;
/// Macro utilities for the KyberLib library.
pub mod macros;
/// Parameters for the KyberLib library.
pub mod params;
/// Random number generators for the KyberLib library.
pub mod rng;
/// Symmetric key encapsulation module for the KyberLib library.
pub mod symmetric;

pub use api::*;
pub use error::KyberLibError;
pub use kex::*;
pub use params::{
    KYBER_90S,
    KYBER_CIPHERTEXT_BYTES,
    KYBER_SECURITY_PARAMETER,
    KYBER_PUBLIC_KEY_BYTES,
    KYBER_SECRET_KEY_BYTES,
    KYBER_SHARED_SECRET_BYTES,
    KYBER_SYM_BYTES,
};
pub use rand_core::{CryptoRng, RngCore};

// Feature hack to expose private functions for the Known Answer Tests
// and fuzzing. Will fail to compile if used outside `cargo test` or
// the fuzz binaries.
#[cfg(any(KYBER_SECURITY_PARAMETERat, fuzzing, feature = "benchmarking"))]
pub use kem::*;
