// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Conditionally compile only if AVX2 feature is enabled.
#![cfg(feature = "avx2")]

use core::arch::x86_64::*;
use serde::{Deserialize, Serialize};

/// Represents the context for AES256-CTR encryption, holding the round keys and counter value.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
#[repr(align(32))] // Ensure proper alignment for AVX2 operations
pub struct Aes256CtrCtx {
    /// The round keys for AES256-CTR encryption.
    pub rkeys: [__m256i; 16],

    /// The counter value for AES256-CTR encryption.
    pub n: __m256i,
}

impl Aes256CtrCtx {
    /// Creates a new `Aes256CtrCtx` instance with all fields initialized to zero.
    pub fn new() -> Self {
        unsafe {
            Self {
                rkeys: [_mm256_setzero_si256(); 16],
                n: _mm256_setzero_si256(),
            }
        }
    }
}

/// Encrypts eight 32-byte data blocks using AES256-CTR encryption with AVX2 instructions.
///
/// # Arguments
///
/// * `out`: A mutable slice of 256 bytes to store the encrypted data.
/// * `n`: The counter value for AES256-CTR encryption.
/// * `rkeys`: The round keys for AES256-CTR encryption.
unsafe fn aesni_encrypt8(out: &mut [u8], mut n: &mut __m256i, rkeys: &[__m256i; 16]) {
    // Prepare the index for interleaving and storing encrypted data blocks.
    let idx: __m128i = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 7, 6, 5, 4, 3, 2, 1, 0);

    // Load and increment the counter value.
    let mut f = _mm256_load_si256(&n);
    n = _mm256_add_epi64(n, _mm256_set_epi64x(8, 0, 0, 0));

    // Shuffle counter values for interleaved encryption.
    let mut f0 = _mm256_shuffle_epi8(f, idx);
    let mut f1 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(1, 0, 0, 0)), idx);
    let mut f2 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(2, 0, 0, 0)), idx);
    let mut f3 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(3, 0, 0, 0)), idx);
    let mut f4 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(4, 0, 0, 0)), idx);
    let mut f5 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(5, 0, 0, 0)), idx);
    let mut f6 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(6, 0, 0, 0)), idx);
    let mut f7 = _mm256_shuffle_epi8(_mm256_add_epi64(f, _mm256_set_epi64x(7, 0, 0, 0)), idx);

    // Perform 14 rounds of AES encryption using AVX2 instructions.
    for i in 0..14 {
        let rkey = _mm256_load_si256(&rkeys[i]);

        f0 = _mm256_xor_si256(f0, rkey);
        f1 = _mm256_xor_si256(f1, rkey);
        f2 = _mm256_xor_si256(f2, rkey);
        f3 = _mm256_xor_si256(f3, rkey);
        f4 = _mm256_xor_si256(f4, rkey);
        f5 = _mm256_xor_si256(f5, rkey);
        f6 = _mm256_xor_si256(f6, rkey);
        f7 = _mm256_xor_si256(f7, rkey);

        // Perform the final round of AES encryption.
        let rkey = _mm256_load_si256(&rkeys[14]);
        f0 = _mm256_xor_si256(f0, rkey);
        f1 = _mm256_xor_si256(f1, rkey);
        f2 = _mm256_xor_si256(f2, rkey);
        f3 = _mm256_xor_si256(f3, rkey);
        f4 = _mm256_xor_si256(f4, rkey);
        f5 = _mm256_xor_si256(f5, rkey);
        f6 = _mm256_xor_si256(f6, rkey);
        f7 = _mm256_xor_si256(f7, rkey);

        // Interleave and store the encrypted data blocks.
        let out0 = _mm256_permutevar8x32_si256(f0, idx);
        let out1 = _mm256_permutevar8x32_si256(f1, idx);
        let out2 = _mm256_permutevar8x32_si256(f2, idx);
        let out3 = _mm256_permutevar8x32_si256(f3, idx);
        let out4 = _mm256_permutevar8x32_si256(f4, idx);
        let out5 = _mm256_permutevar8x32_si256(f5, idx);
        let out6 = _mm256_permutevar8x32_si256(f6, idx);
        let out7 = _mm256_permutevar8x32_si256(f7, idx);

        _mm256_store_si256(&mut out[0..32], out0);
        _mm256_store_si256(&mut out[32..64], out1);
        _mm256_store_si256(&mut out[64..96], out2);
        _mm256_store_si256(&mut out[96..128], out3);
        _mm256_store_si256(&mut out[128..160], out4);
        _mm256_store_si256(&mut out[160..192], out5);
        _mm256_store_si256(&mut out[192..224], out6);
        _mm256_store_si256(&mut out[224..256], out7);
    }
    _mm256_store_si256(&mut n, f);
}
