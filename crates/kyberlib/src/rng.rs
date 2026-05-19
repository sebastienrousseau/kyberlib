// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! RNG helpers.
//!
//! kyberlib's public surface consumes generic [`rand_core::RngCore`]
//! + [`rand_core::CryptoRng`] — see the function signatures in
//! [`crate::api`] and [`crate::ml_kem`]. The single helper exported
//! here ([`randombytes`](crate::rng::randombytes)) wraps
//! `RngCore::try_fill_bytes` to surface kyberlib's
//! [`KyberLibError::RandomBytesGeneration`](crate::KyberLibError::RandomBytesGeneration)
//! variant on external-RNG faults.

use crate::KyberLibError;
use rand_core::{CryptoRng, RngCore};

/// Fills a buffer `x` with `len` bytes of random data.
///
/// This function uses a random number generator (RNG) that satisfies both
/// the `RngCore` and `CryptoRng` traits. The RNG is used to generate `len`
/// random bytes and fill the buffer `x` with these bytes.
///
/// # Arguments
///
/// * `x` - A mutable slice of bytes to be filled with random data.
/// * `len` - The number of random bytes to generate.
/// * `rng` - A mutable reference to the RNG.
///
/// # Errors
///
/// If the RNG fails to generate the required number of bytes, an error
/// of type `KyberLibError::RandomBytesGeneration` is returned.
///
/// # Examples
///
/// ```
/// use kyberlib::rng::randombytes;
/// use rand_core::OsRng;
///
/// let mut buffer = [0u8; 32];
/// let len = buffer.len();
/// randombytes(&mut buffer, len, &mut OsRng).expect("OsRng cannot fail");
/// ```
///
/// # Notes
///
/// Ensure that the length of the buffer `x` is at least `len` bytes,
/// otherwise the function will panic due to out-of-bounds memory access.
pub fn randombytes<R>(
    x: &mut [u8],
    len: usize,
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: RngCore + CryptoRng,
{
    if len > x.len() {
        return Err(KyberLibError::InvalidLength);
    }

    rng.try_fill_bytes(&mut x[..len])
        .map_err(|_| KyberLibError::RandomBytesGeneration)
}
