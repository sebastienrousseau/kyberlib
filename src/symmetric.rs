// Copyright © 2023 KyberLib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(dead_code)]

#[cfg(feature = "90s")]
use crate::aes256ctr::*;
#[cfg(not(feature = "90s"))]
use crate::{fips202::*, params::*};
#[cfg(feature = "90s")]
use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "90s-fixslice")]
use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
#[cfg(feature = "90s-fixslice")]
type Aes256Ctr = ctr::Ctr32BE<aes::Aes256>;

#[cfg(feature = "90s")]
pub const AES256CTR_BLOCKBYTES: usize = 64;

#[cfg(feature = "90s")]
pub const XOF_BLOCKBYTES: usize = AES256CTR_BLOCKBYTES;
#[cfg(not(feature = "90s"))]
pub(crate) const XOF_BLOCKBYTES: usize = SHAKE128_RATE;

#[cfg(not(feature = "90s"))]
pub(crate) type XofState = KeccakState;

#[cfg(feature = "90s")]
pub type XofState = Aes256CtrCtx;

/// Keccak state for absorbing data
#[derive(Copy, Clone)]
pub(crate) struct KeccakState {
    pub(crate) s: [u64; 25],
    pub(crate) pos: usize,
}

impl KeccakState {
    /// Creates a new KeccakState
    pub(crate) fn new() -> Self {
        KeccakState {
            s: [0u64; 25],
            pos: 0usize,
        }
    }

    /// Resets the KeccakState
    pub(crate) fn reset(&mut self) {
        self.s = [0u64; 25];
        self.pos = 0;
    }
}

/// Computes SHA3-256 hash
#[cfg(not(feature = "90s"))]
pub(crate) fn hash_h(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_256(out, input, inlen);
}

/// Computes SHA2-256 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_h(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha256::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}

/// Computes SHA3-512 hash
#[cfg(not(feature = "90s"))]
pub(crate) fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {
    sha3_512(out, input, inlen);
}

/// Computes SHA2-512 hash in 90s mode
#[cfg(feature = "90s")]
pub fn hash_g(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha512::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}

/// Absorbs input data into the XOF state in non-90s mode
#[cfg(not(feature = "90s"))]
pub(crate) fn xof_absorb(state: &mut XofState, input: &[u8], x: u8, y: u8) {
    kyber_shake128_absorb(state, input, x, y);
}

/// Absorbs input data into the XOF state in 90s mode
#[cfg(feature = "90s")]
pub fn xof_absorb(state: &mut XofState, input: &[u8], x: u8, y: u8) {
    let mut nonce = [0u8; 12];
    nonce[0] = x;
    nonce[1] = y;
    aes256ctr_init(state, input, nonce);
}

/// Squeezes XOF data into output in non-90s mode
#[cfg(not(feature = "90s"))]
pub(crate) fn xof_squeezeblocks(out: &mut [u8], outblocks: usize, state: &mut XofState) {
    kyber_shake128_squeezeblocks(out, outblocks, state);
}

/// Squeezes XOF data into output in 90s mode
#[cfg(feature = "90s")]
pub fn xof_squeezeblocks(out: &mut [u8], outblocks: usize, state: &mut XofState) {
    aes256ctr_squeezeblocks(out, outblocks, state);
}

/// Pseudo-random function (PRF) in non-90s mode
#[cfg(not(feature = "90s"))]
pub(crate) fn prf(out: &mut [u8], outbytes: usize, key: &[u8], nonce: u8) {
    shake256_prf(out, outbytes, key, nonce);
}

/// Pseudo-random function (PRF) in 90s mode
#[cfg(feature = "90s")]
pub fn prf(out: &mut [u8], _outbytes: usize, key: &[u8], nonce: u8) {
    #[cfg(feature = "90s-fixslice")]
    {
        // RustCrypto fixslice
        let mut expnonce = [0u8; 16];
        expnonce[0] = nonce;
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(&expnonce);
        let mut cipher = Aes256Ctr::new(key, iv);
        cipher.apply_keystream(out)
    }
    #[cfg(not(feature = "90s-fixslice"))]
    // Pornin bitslice
    aes256ctr_prf(out, _outbytes, &key, nonce);
}

/// Key derivation function (KDF) in non-90s mode
#[cfg(not(feature = "90s"))]
pub(crate) fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    shake256(out, KYBER_SHARED_SECRET_BYTES, input, inlen);
}

/// Key derivation function (KDF) in 90s mode
#[cfg(feature = "90s")]
pub fn kdf(out: &mut [u8], input: &[u8], inlen: usize) {
    let mut hasher = Sha256::new();
    hasher.update(&input[..inlen]);
    let digest = hasher.finalize();
    out[..digest.len()].copy_from_slice(&digest);
}

/// Absorb step of the SHAKE128 specialized for the Kyber context
#[cfg(not(feature = "90s"))]
fn kyber_shake128_absorb(s: &mut KeccakState, input: &[u8], x: u8, y: u8) {
    let mut extseed = [0u8; KYBER_SYM_BYTES + 2];
    extseed[..KYBER_SYM_BYTES].copy_from_slice(input);
    extseed[KYBER_SYM_BYTES] = x;
    extseed[KYBER_SYM_BYTES + 1] = y;
    shake128_absorb_once(s, &extseed, KYBER_SYM_BYTES + 2);
}

/// Squeeze step of SHAKE128 XOF in non-90s mode
#[cfg(not(feature = "90s"))]
fn kyber_shake128_squeezeblocks(output: &mut [u8], nblocks: usize, s: &mut KeccakState) {
    shake128_squeezeblocks(output, nblocks, s);
}

/// Usage of SHAKE256 as a PRF in non-90s mode
#[cfg(not(feature = "90s"))]
fn shake256_prf(output: &mut [u8], outlen: usize, key: &[u8], nonce: u8) {
    let mut extkey = [0u8; KYBER_SYM_BYTES + 1];
    extkey[..KYBER_SYM_BYTES].copy_from_slice(key);
    extkey[KYBER_SYM_BYTES] = nonce;
    shake256(output, outlen, &extkey, KYBER_SYM_BYTES + 1);
}
