// Copyright © 2023 KyberLib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Error types for the failure modes in Kyber key exchange.
#[derive(Debug, PartialEq)]
pub enum KyberLibError {
    /// One or more inputs to a function are incorrectly sized. A likely cause of this is
    /// two parties using different security levels while trying to negotiate a key exchange.
    InvalidInput,

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
            KyberLibError::RandomBytesGeneration => write!(f, "Random bytes generation function failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KyberLibError {}
