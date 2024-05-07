// Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(test)]

// Import the necessary crates for testing in a no_std environment
extern crate alloc;

use alloc::string::ToString; // For converting Display to String
use kyberlib::KyberLibError;

#[test]
fn test_kyber_lib_error_display() {
    let error = KyberLibError::InvalidInput;
    assert_eq!(error.to_string(), "Function input is of incorrect length");

    let error = KyberLibError::Decapsulation;
    assert_eq!(
        error.to_string(),
        "Decapsulation Failure, unable to obtain shared secret from ciphertext"
    );

    let error = KyberLibError::RandomBytesGeneration;
    assert_eq!(error.to_string(), "Random bytes generation function failed");
}
