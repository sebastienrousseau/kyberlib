// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Fuzz arbitrary byte slices through the public-key length validation
//! path in `encapsulate`. Same rationale as `fuzz_ct_parse`.

#![no_main]
use kyberlib::encapsulate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rng = rand::thread_rng();
    let _ = encapsulate(data, &mut rng);
});
