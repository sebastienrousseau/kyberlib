// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS 203 input checks: §7.2 (encapsulation key modulus check) and
//! §7.3 (decapsulation key hash check).

use crate::kem::{dk_bytes, ek_bytes};
use crate::params::{KYBER_POLY_BYTES, KYBER_Q, KYBER_SYM_BYTES};
use crate::symmetric::hash_h;

/// FIPS 203 §7.2 modulus check on the encoded polynomial vector of an
/// encapsulation key: every 12-bit coefficient must be below q.
///
/// This is equivalent to `ByteEncode12(ByteDecode12(ek)) == ek` and
/// works on public data, so it need not run in constant time.
pub(crate) fn coefficients_reduced(polyvec_bytes: &[u8]) -> bool {
    let q = KYBER_Q as u16;
    polyvec_bytes.as_chunks::<3>().0.iter().all(|t| {
        let lo = u16::from(t[0]) | (u16::from(t[1] & 0x0F) << 8);
        let hi = u16::from(t[1] >> 4) | (u16::from(t[2]) << 4);
        lo < q && hi < q
    })
}

/// FIPS 203 §7.3 hash check on a decapsulation key for parameter set
/// `P`: the stored `H(ek)` must equal the hash of the embedded `ek`.
pub(crate) fn dk_hash_check<P: crate::paramsets::MlKemParams>(
    dk: &[u8],
) -> bool {
    let sk_pv = P::K * KYBER_POLY_BYTES;
    let ek_len = ek_bytes::<P>();
    let h_at = sk_pv + ek_len;
    if dk.len() != dk_bytes::<P>() {
        return false;
    }
    let mut h = [0u8; KYBER_SYM_BYTES];
    hash_h(&mut h, &dk[sk_pv..h_at], ek_len);
    h == dk[h_at..h_at + KYBER_SYM_BYTES]
}
