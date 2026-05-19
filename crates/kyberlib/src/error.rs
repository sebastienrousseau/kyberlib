// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types.
//!
//! Every fallible public function in kyberlib returns
//! [`Result<T, KyberLibError>`]. The enum is `#[non_exhaustive]` so
//! future backend-specific variants (the planned `fips` and `verified`
//! features) can be added without a major-version bump.

/// Error types for the failure modes in kyberlib.
///
/// Marked `#[non_exhaustive]` (since v0.0.7, #130) so future variants
/// — e.g. backend-specific errors from the planned `fips` (#170) and
/// `verified` (#171) features — can be added without a major-version
/// bump.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum KyberLibError {
    /// One or more inputs to a function are incorrectly sized. A likely cause of this is
    /// two parties using different security levels while trying to negotiate a key exchange.
    InvalidInput,

    /// Error when generating keys
    InvalidKey,

    /// The length of the input buffer is invalid.
    InvalidLength,

    /// The ciphertext was unable to be authenticated. The shared secret was not decapsulated.
    Decapsulation,

    /// Error trying to fill random bytes (i.e., external (hardware) RNG modules can fail).
    RandomBytesGeneration,
}

impl core::fmt::Display for KyberLibError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            KyberLibError::InvalidInput => write!(f, "Function input is of incorrect length"),
            KyberLibError::Decapsulation => write!(
                f,
                "Decapsulation Failure, unable to obtain shared secret from ciphertext"
            ),
            KyberLibError::RandomBytesGeneration => {
                write!(f, "Random bytes generation function failed")
            }
            KyberLibError::InvalidKey => {
                write!(f, "The secret and public key given does not match.")
            },
            KyberLibError::InvalidLength => {
                write!(f, "The length of the input buffer is invalid.")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KyberLibError {}
