// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Critical fuzz target — feeds arbitrary bytes to `decapsulate` and asserts
//! the FIPS 203 implicit-rejection contract: decap must NEVER panic, and
//! must NEVER branch on validity. The harness only checks the no-panic /
//! no-abort half here (the constant-time half is in `scripts/dudect.sh`).
//!
//! The fuzzer drives two arms:
//!   1. Pair (ciphertext, secret_key) of the correct lengths but arbitrary
//!      contents. Both should always return `Ok(_)`.
//!   2. Either or both buffers truncated. Must return `Err(InvalidInput)`,
//!      never panic.

#![no_main]
use kyberlib::{
    decapsulate, KYBER_CIPHERTEXT_BYTES, KYBER_SECRET_KEY_BYTES,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least one byte to decide the path.
    if data.is_empty() {
        return;
    }
    let mode = data[0] & 0b11;
    let body = &data[1..];

    match mode {
        // Mode 0: well-formed lengths, arbitrary content. Always Ok.
        0 => {
            if body.len()
                < KYBER_CIPHERTEXT_BYTES + KYBER_SECRET_KEY_BYTES
            {
                return;
            }
            let ct = &body[..KYBER_CIPHERTEXT_BYTES];
            let sk = &body[KYBER_CIPHERTEXT_BYTES
                ..KYBER_CIPHERTEXT_BYTES + KYBER_SECRET_KEY_BYTES];
            // Implicit rejection: this must succeed regardless of validity.
            let _ = decapsulate(ct, sk);
        }
        // Mode 1+2+3: arbitrary lengths. Should never panic; should return
        // InvalidInput when sizes are wrong.
        _ => {
            let mid = body.len() / 2;
            let (ct, sk) = body.split_at(mid);
            let _ = decapsulate(ct, sk);
        }
    }
});
