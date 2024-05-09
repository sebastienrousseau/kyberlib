// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(test)]

// Import the necessary crates for testing in a no_std environment
extern crate alloc;

use alloc::string::ToString; // For converting Display to String
use kyberlib::KyberLibError;

#[test]
fn test_kyber_lib_error_display() {
    let error = KyberLibError::InvalidInput;
    assert_eq!(
        error.to_string(),
        "Function input is of incorrect length"
    );

    let error = KyberLibError::Decapsulation;
    assert_eq!(
        error.to_string(),
        "Decapsulation Failure, unable to obtain shared secret from ciphertext"
    );

    let error = KyberLibError::RandomBytesGeneration;
    assert_eq!(
        error.to_string(),
        "Random bytes generation function failed"
    );

    let error = KyberLibError::InvalidKey;
    assert_eq!(
        error.to_string(),
        "The secret and public key given does not match."
    );
}

#[test]
fn test_kyber_lib_error_partial_eq() {
    let error1 = KyberLibError::InvalidInput;
    let error2 = KyberLibError::InvalidInput;
    assert_eq!(error1, error2);

    let error1 = KyberLibError::Decapsulation;
    let error2 = KyberLibError::Decapsulation;
    assert_eq!(error1, error2);

    let error1 = KyberLibError::RandomBytesGeneration;
    let error2 = KyberLibError::RandomBytesGeneration;
    assert_eq!(error1, error2);

    let error1 = KyberLibError::InvalidKey;
    let error2 = KyberLibError::InvalidKey;
    assert_eq!(error1, error2);

    let error1 = KyberLibError::InvalidInput;
    let error2 = KyberLibError::Decapsulation;
    assert_ne!(error1, error2);
}

#[cfg(feature = "std")]
#[test]
fn test_kyber_lib_error_std_error() {
    let error = KyberLibError::InvalidInput;
    let _std_error: &dyn std::error::Error = &error;
}
