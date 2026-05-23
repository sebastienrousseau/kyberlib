// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Round-trip property: for any RNG byte sequence we feed kyberlib via
//! a wrapper PRNG, gen → encap → decap must always agree on the shared
//! secret. Catches any non-determinism in the IND-CCA construction.

#![no_main]
use kyberlib::{decapsulate, encapsulate, keypair};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, Error, RngCore};

/// Deterministic PRNG seeded by libFuzzer input. Cycles `data` and
/// `try_fill_bytes`-only — we never want a real OS RNG inside fuzz.
struct CyclingRng<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CyclingRng<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl RngCore for CyclingRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.bytes.is_empty() {
            for b in dest {
                *b = 0;
            }
            return;
        }
        for b in dest {
            *b = self.bytes[self.pos % self.bytes.len()];
            self.pos = self.pos.wrapping_add(1);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CyclingRng<'_> {}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let mut rng = CyclingRng::new(data);
    let keys = match keypair(&mut rng) {
        Ok(k) => k,
        Err(_) => return,
    };
    let (ct, ss_a) = match encapsulate(&keys.public, &mut rng) {
        Ok(p) => p,
        Err(_) => return,
    };
    let ss_b = match decapsulate(&ct, &keys.secret) {
        Ok(s) => s,
        Err(_) => return,
    };
    assert_eq!(
        ss_a, ss_b,
        "round-trip shared-secret mismatch — encapsulation and decapsulation must agree"
    );
});
