// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
/// # use rand_core::OsRng;
/// # use crate::kyberlib::rng::randombytes;
/// let mut buffer = [0u8; 32];
/// let buffer_len = buffer.len();
/// let result = randombytes(&mut buffer, buffer_len, &mut OsRng);
/// assert!(result.is_ok());
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
    rng.try_fill_bytes(&mut x[..len])
        .map_err(|_| KyberLibError::RandomBytesGeneration)
}
