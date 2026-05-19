// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Fuzz arbitrary byte slices through the ciphertext-length validation
//! path. Verifies size checking surfaces `InvalidInput` cleanly rather
//! than panicking on truncated / oversized input.

#![no_main]
use kyberlib::decapsulate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A dummy secret key of correct length. We're fuzzing the ct length
    // gate, not the secret. A zero-filled sk is fine for path coverage.
    let sk = vec![0u8; kyberlib::KYBER_SECRET_KEY_BYTES];
    let _ = decapsulate(data, &sk);
});
