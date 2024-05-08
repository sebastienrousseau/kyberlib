// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # KyberLib Macros
//!
//! A collection of utility macros for various operations like assertions, logging, and executing tasks,
//! specifically designed for `no_std` environments in Rust. These macros provide essential functionalities
//! like logging, assertions, and value comparisons without relying on the standard library.

/// Asserts that a given expression is true. Panics if the assertion fails.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_assert;
/// kyberlib_assert!(1 + 1 == 2);
/// ```
#[macro_export]
macro_rules! kyberlib_assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            // Handle assertion failure in your custom way, e.g., by logging or panic
            // You can define your custom panic handler in a no_std environment.
            panic!("Assertion failed: {}", stringify!($cond));
        }
    };
}

/// Returns the minimum of the given values.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_min;
/// let min = kyberlib_min!(1, 2, 3);
/// assert_eq!(min, 1);
/// ```
#[macro_export]
macro_rules! kyberlib_min {
    ($x:expr $(, $xs:expr)*) => {{
        let mut min = $x;
        $(min = if $xs < min { $xs } else { min };)*
        min
    }};
}

/// Returns the maximum of the given values.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_max;
/// let max = kyberlib_max!(1, 2, 3);
/// assert_eq!(max, 3);
/// ```
#[macro_export]
macro_rules! kyberlib_max {
    ($x:expr $(, $xs:expr)*) => {{
        let mut max = $x;
        $(max = if $xs > max { $xs } else { max };)*
        max
    }};
}

/// Generates a public and private key pair for CCA-secure Kyber key encapsulation mechanism.
///
/// # Arguments
///
/// * `pk` - Output public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes).
/// * `sk` - Output private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes).
/// * `_rng` - Random number generator implementing RngCore + CryptoRng.
/// * `_seed` - Optional seed for key generation.
///
/// # Errors
///
/// Returns a `KyberLibError` on failure.
#[macro_export]
macro_rules! kyberlib_generate_key_pair {
    ($pk:expr, $sk:expr, $rng:expr, $seed:expr) => {
        kyberlib::kem::generate_key_pair($pk, $sk, $rng, $seed)
    };
}

/// Generates cipher text and a shared secret for a given public key.
///
/// # Arguments
///
/// * `ct` - Output cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes).
/// * `ss` - Output shared secret (an already allocated array of CRYPTO_BYTES bytes).
/// * `pk` - Input public key (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes).
/// * `_rng` - Random number generator implementing RngCore + CryptoRng.
/// * `_seed` - Optional seed for random number generation.
///
/// # Errors
///
/// Returns a `KyberLibError` on failure.
#[macro_export]
macro_rules! kyberlib_encrypt_message {
    ($ct:expr, $ss:expr, $pk:expr, $rng:expr, $seed:expr) => {
        kyberlib::kem::encrypt_message($ct, $ss, $pk, $rng, $seed)
    };
}

/// Generates a shared secret for a given cipher text and private key.
///
/// # Arguments
///
/// * `ss` - Output shared secret (an already allocated array of CRYPTO_BYTES bytes).
/// * `ct` - Input cipher text (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes).
/// * `sk` - Input private key (an already allocated array of CRYPTO_SECRETKEYBYTES bytes).
///
/// On failure, `ss` will contain a pseudo-random value.
#[macro_export]
macro_rules! kyberlib_decrypt_message {
    ($ss:expr, $ct:expr, $sk:expr) => {
        kyberlib::kem::decrypt_message($ss, $ct, $sk)
    };
}


