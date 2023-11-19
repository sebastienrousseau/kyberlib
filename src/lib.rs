// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//!
//! # `kyberlib` 🦀
//!
//! [![kyberlib](https://via.placeholder.com/1500x500.png/000000/FFFFFF?text=kyberlib)](https://kyberlib.com/ "kyberlib - A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography")
//!
//! A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography
//!
//! [![Crates.io](https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge&color=success&labelColor=27A006)](https://crates.io/crates/kyberlib "Crates.io")
//! [![Lib.rs](https://img.shields.io/badge/lib.rs-v0.0.1-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4)](https://lib.rs/crates/kyberlib "Lib.rs")
//! [![License](https://img.shields.io/crates/l/kyberlib.svg?style=for-the-badge&color=007EC6&labelColor=03589B)](MIT  "MIT")
//! [![Rust](https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust)](https://www.rust-lang.org "Rust")
//!
//! ## Overview
//!
//! A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography
//!
//! ## Features
//!
//! - ...
//! - ...
//! - ...
//!
//! ## Usage
//!
//! Add the following to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! kyberlib = "0.0.1"
//! serde = { version = "1.0", features = ["derive"] }
//! serde_json = "1.0"
//! ```
//!
//! ## Examples
//!
//! Check out the examples folder for helpful snippets of code that
//! demonstrate how to use the `kyberlib` library. You can also check out
//! the [documentation](https://docs.rs/kyberlib) for more information on
//! how to use the library.
//!
//! ```rust
//!    use kyberlib::kyberlib;
//!
//! ```
//!
//! ## License
//!
//! The project is licensed under the terms of the MIT license.
//!
#![forbid(unsafe_code)]
#![forbid(unreachable_pub)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![doc(
    html_favicon_url = "https://kura.pro/kyberlib/images/favicon.ico",
    html_logo_url = "https://kura.pro/kyberlib/images/logos/kyberlib.svg",
    html_root_url = "https://docs.rs/kyberlib"
)]
#![crate_name = "kyberlib"]
#![crate_type = "lib"]

/// The `loggers` module contains the loggers for the library.
pub mod loggers;

/// The `aes256` module contains the AES-256 implementation.
pub mod aes256;

/// The `macros` module contains functions for generating macros.
pub mod macros;

use serde::{Deserialize, Serialize};
use std::error::Error;

#[non_exhaustive]
#[derive(
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]

#[allow(non_camel_case_types)]
/// kyberlib is a data structure that ...
pub struct kyberlib {
    // Add any data fields needed here
}

/// This is the main entry point for the kyberlib library.
pub fn run() -> Result<(), Box<dyn Error>> {
    // Add your code here
    let name = "kyberlib";
    println!("Hello, {}!", { name }.to_uppercase());
    Ok(())
}


impl kyberlib {
    /// Creates a new instance of kyberlib
    pub fn new() -> Self {
        Self {
            // Initialize any data fields here
        }
    }
}

impl Default for kyberlib {
    /// Creates a new instance of kyberlib with default values
    fn default() -> Self {
        Self::new()
    }
}
