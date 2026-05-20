#![allow(clippy::precedence)]
use crate::{params::*, poly::*};

#[derive(Clone)]
pub(crate) struct Polyvec {
    pub(crate) vec: [Poly; KYBER_SECURITY_PARAMETER],
}

impl Copy for Polyvec {}

impl Polyvec {
    pub(crate) fn new() -> Self {
        Polyvec {
            vec: [Poly::new(); KYBER_SECURITY_PARAMETER],
        }
    }
}

/// Name:  polyvec_compress
///
/// Description: Compress and serialize vector of polynomials
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVEC_COMPRESSED_BYTES)
///  - const Polyvec a: input vector of polynomials
pub(crate) fn polyvec_compress(r: &mut [u8], a: Polyvec) {
    #[cfg(feature = "kyber1024")]
    {
        let mut t = [0u16; 8];
        let mut idx = 0usize;
        for i in 0..KYBER_SECURITY_PARAMETER {
            for j in 0..KYBER_N / 8 {
                for (k, t_k) in t.iter_mut().enumerate() {
                    *t_k = a.vec[i].coeffs[8 * j + k] as u16;
                    *t_k = t_k.wrapping_add(
                        (((*t_k as i16) >> 15) & KYBER_Q as i16) as u16,
                    );
                    let mut tmp: u64 =
                        ((*t_k as u64) << 11) + (KYBER_Q as u64 / 2);
                    tmp *= 20642679;
                    tmp >>= 36;
                    *t_k = (tmp as u16) & 0x7ff;
                }
                r[idx] = (t[0]) as u8;
                r[idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                r[idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                r[idx + 3] = (t[2] >> 2) as u8;
                r[idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                r[idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                r[idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                r[idx + 7] = (t[5] >> 1) as u8;
                r[idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                r[idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                r[idx + 10] = (t[7] >> 3) as u8;
                idx += 11
            }
        }
    }

    #[cfg(not(feature = "kyber1024"))]
    {
        let mut t = [0u16; 4];
        let mut idx = 0usize;
        for i in 0..KYBER_SECURITY_PARAMETER {
            for j in 0..KYBER_N / 4 {
                for (k, t_k) in t.iter_mut().enumerate() {
                    *t_k = a.vec[i].coeffs[4 * j + k] as u16;
                    *t_k = t_k.wrapping_add(
                        (((*t_k as i16) >> 15) & KYBER_Q as i16) as u16,
                    );
                    let mut tmp: u64 =
                        ((*t_k as u64) << 10) + (KYBER_Q as u64 / 2);
                    tmp *= 20642679;
                    tmp >>= 36;
                    *t_k = (tmp as u16) & 0x3ff;
                }
                r[idx] = (t[0]) as u8;
                r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                r[idx + 4] = (t[3] >> 2) as u8;
                idx += 5;
            }
        }
    }
}

/// Generic-over-`MlKemParams` port of [`polyvec_compress`].
///
/// Takes the polynomials as a `&[Poly]` slice (the caller is
/// responsible for passing exactly `P::K` polynomials) and dispatches
/// the per-set compression bit-width through `P::DU`.
///
/// This is the **first concrete proof** that the
/// [`crate::paramsets::MlKemParams`] foundation can carry the
/// reference backend's algorithm code without needing
/// `feature(generic_const_exprs)`. The remaining ~14 reference
/// primitives (`indcpa_*`, `poly_compress`, `cbd*`, `gen_matrix`,
/// etc.) follow this same template — pass slices, drive the
/// per-set numeric parameters off `P`, write to byte-arrays whose
/// size is `P::*_BYTES`.
///
/// # Panics
///
/// Panics if `polys.len() != P::K` (debug-assertion in test mode;
/// silent loop overrun otherwise — same contract as the existing
/// `polyvec_compress`).
///
/// # Output length
///
/// `r` must have space for `polyvec_compressed_len::<P>()` bytes:
/// `32 * P::K * P::DU` (= 320·K for DU=10, 352·K for DU=11).
#[allow(dead_code)] // Wired in incrementally as the algorithm port lands; see #130c.
pub(crate) fn polyvec_compress_generic<
    P: crate::paramsets::MlKemParams,
>(
    r: &mut [u8],
    polys: &[Poly],
) {
    debug_assert_eq!(
        polys.len(),
        P::K,
        "polyvec must have K polynomials"
    );

    let mut idx = 0usize;

    match P::DU {
        10 => {
            // ML-KEM-512 / ML-KEM-768 path: d_u = 10. Same bit-packing
            // as the existing `#[cfg(not(feature = "kyber1024"))]` branch.
            let mut t = [0u16; 4];
            for poly in polys.iter() {
                for j in 0..KYBER_N / 4 {
                    for (k, t_k) in t.iter_mut().enumerate() {
                        *t_k = poly.coeffs[4 * j + k] as u16;
                        *t_k = t_k.wrapping_add(
                            (((*t_k as i16) >> 15) & KYBER_Q as i16)
                                as u16,
                        );
                        let mut tmp: u64 = ((*t_k as u64) << 10)
                            + (KYBER_Q as u64 / 2);
                        tmp *= 20642679;
                        tmp >>= 36;
                        *t_k = (tmp as u16) & 0x3ff;
                    }
                    r[idx] = (t[0]) as u8;
                    r[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                    r[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                    r[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                    r[idx + 4] = (t[3] >> 2) as u8;
                    idx += 5;
                }
            }
        }
        11 => {
            // ML-KEM-1024 path: d_u = 11.
            let mut t = [0u16; 8];
            for poly in polys.iter() {
                for j in 0..KYBER_N / 8 {
                    for (k, t_k) in t.iter_mut().enumerate() {
                        *t_k = poly.coeffs[8 * j + k] as u16;
                        *t_k = t_k.wrapping_add(
                            (((*t_k as i16) >> 15) & KYBER_Q as i16)
                                as u16,
                        );
                        let mut tmp: u64 = ((*t_k as u64) << 11)
                            + (KYBER_Q as u64 / 2);
                        tmp *= 20642679;
                        tmp >>= 36;
                        *t_k = (tmp as u16) & 0x7ff;
                    }
                    r[idx] = (t[0]) as u8;
                    r[idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                    r[idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                    r[idx + 3] = (t[2] >> 2) as u8;
                    r[idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                    r[idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                    r[idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                    r[idx + 7] = (t[5] >> 1) as u8;
                    r[idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                    r[idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                    r[idx + 10] = (t[7] >> 3) as u8;
                    idx += 11;
                }
            }
        }
        _ => {
            // P::DU is fixed at the trait-impl level to 10 or 11 — see
            // crate::paramsets. The `_` arm is unreachable in practice
            // but `match` requires exhaustive patterns on `usize`.
            unreachable!("DU must be 10 or 11 per FIPS 203 §6");
        }
    }
}

/// Compressed-polyvec byte length for parameter set `P`: `32 * P::K * P::DU`.
#[allow(dead_code)] // Wired alongside polyvec_compress_generic.
pub(crate) const fn polyvec_compressed_len<
    P: crate::paramsets::MlKemParams,
>() -> usize {
    32 * P::K * P::DU
}

/// Name:  polyvec_decompress
///
/// Description: De-serialize and decompress vector of polynomials;
///  approximate inverse of polyvec_compress
///
/// Arguments:   - Polyvec r:   output vector of polynomials
///  - [u8] a: input byte array (of length KYBER_POLYVEC_COMPRESSED_BYTES)
pub(crate) fn polyvec_decompress(r: &mut Polyvec, a: &[u8]) {
    #[cfg(feature = "kyber1024")]
    {
        let mut t = [0u16; 8];
        let mut idx = 0usize;
        for i in 0..KYBER_SECURITY_PARAMETER {
            for j in 0..KYBER_N / 8 {
                t[0] = (a[idx]) as u16 | (a[idx + 1] as u16) << 8;
                t[1] =
                    (a[idx + 1] >> 3) as u16 | (a[idx + 2] as u16) << 5;
                t[2] = (a[idx + 2] >> 6) as u16
                    | (a[idx + 3] as u16) << 2
                    | (a[idx + 4] as u16) << 10;
                t[3] =
                    (a[idx + 4] >> 1) as u16 | (a[idx + 5] as u16) << 7;
                t[4] =
                    (a[idx + 5] >> 4) as u16 | (a[idx + 6] as u16) << 4;
                t[5] = (a[idx + 6] >> 7) as u16
                    | (a[idx + 7] as u16) << 1
                    | (a[idx + 8] as u16) << 9;
                t[6] =
                    (a[idx + 8] >> 2) as u16 | (a[idx + 9] as u16) << 6;
                t[7] = (a[idx + 9] >> 5) as u16
                    | (a[idx + 10] as u16) << 3;
                idx += 11;

                for k in 0..8 {
                    r.vec[i].coeffs[8 * j + k] =
                        (((t[k] & 0x7FF) as u32 * KYBER_Q as u32
                            + 1024)
                            >> 11) as i16;
                }
            }
        }
    }

    #[cfg(not(feature = "kyber1024"))]
    {
        let mut idx = 0usize;
        let mut t = [0u16; 4];
        for i in 0..KYBER_SECURITY_PARAMETER {
            for j in 0..KYBER_N / 4 {
                t[0] = (a[idx]) as u16 | (a[idx + 1] as u16) << 8;
                t[1] =
                    (a[idx + 1] >> 2) as u16 | (a[idx + 2] as u16) << 6;
                t[2] =
                    (a[idx + 2] >> 4) as u16 | (a[idx + 3] as u16) << 4;
                t[3] =
                    (a[idx + 3] >> 6) as u16 | (a[idx + 4] as u16) << 2;
                idx += 5;

                for (k, item) in t.iter().enumerate() {
                    r.vec[i].coeffs[4 * j + k] =
                        ((((*item as u32) & 0x3FF) * KYBER_Q as u32
                            + 512)
                            >> 10) as i16;
                }
            }
        }
    }
}

/// Name:  polyvec_tobytes
///
/// Description: Serialize vector of polynomials
///
/// Arguments:   - [u8] r: output byte array (needs space for KYBER_POLYVEC_BYTES)
///  - const Polyvec a: input vector of polynomials
pub(crate) fn polyvec_tobytes(r: &mut [u8], a: &Polyvec) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_tobytes(&mut r[i * KYBER_POLY_BYTES..], a.vec[i]);
    }
}

/// Name:  polyvec_frombytes
///
/// Description: De-serialize vector of polynomials;
///  inverse of polyvec_tobytes
///
/// Arguments:   - [u8] r: output byte array
///  - const Polyvec a: input vector of polynomials (of length KYBER_POLYVEC_BYTES)
pub(crate) fn polyvec_frombytes(r: &mut Polyvec, a: &[u8]) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_frombytes(&mut r.vec[i], &a[i * KYBER_POLY_BYTES..]);
    }
}

/// Name:  polyvec_ntt
///
/// Description: Apply forward NTT to all elements of a vector of polynomials
///
/// Arguments:   - Polyvec r: in/output vector of polynomials
pub(crate) fn polyvec_ntt(r: &mut Polyvec) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_ntt(&mut r.vec[i]);
    }
}

/// Name:  polyvec_invntt
///
/// Description: Apply inverse NTT to all elements of a vector of polynomials
///
/// Arguments:   - Polyvec r: in/output vector of polynomials
pub(crate) fn polyvec_invntt_tomont(r: &mut Polyvec) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_invntt_tomont(&mut r.vec[i]);
    }
}

/// Name:  polyvec_basemul_acc_montgomery
///
/// Description: Pointwise multiply elements of a and b and accumulate into r
///
/// Arguments: - poly *r:  output polynomial
///  - const Polyvec a: first input vector of polynomials
///  - const Polyvec b: second input vector of polynomials
pub(crate) fn polyvec_basemul_acc_montgomery(
    r: &mut Poly,
    a: &Polyvec,
    b: &Polyvec,
) {
    let mut t = Poly::new();
    poly_basemul(r, &a.vec[0], &b.vec[0]);
    for i in 1..KYBER_SECURITY_PARAMETER {
        poly_basemul(&mut t, &a.vec[i], &b.vec[i]);
        poly_add(r, &t);
    }
    poly_reduce(r);
}

/// Name:  polyvec_reduce
///
/// Description: Applies Barrett reduction to each coefficient
///  of each element of a vector of polynomials
///  for details of the Barrett reduction see comments in reduce.c
///
/// Arguments:   - poly *r:   input/output polynomial
pub(crate) fn polyvec_reduce(r: &mut Polyvec) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_reduce(&mut r.vec[i]);
    }
}

/// Name:  polyvec_add
///
/// Description: Add vectors of polynomials
///
/// Arguments: - Polyvec r:   output vector of polynomials
///  - const Polyvec b: second input vector of polynomials
pub(crate) fn polyvec_add(r: &mut Polyvec, b: &Polyvec) {
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_add(&mut r.vec[i], &b.vec[i]);
    }
}

#[cfg(test)]
mod compress_generic_tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;

    /// Build a deterministic test polyvec for the active parameter set
    /// (this build's KYBER_SECURITY_PARAMETER, which equals
    /// MlKem<active>::K). Uses a small but non-trivial coefficient
    /// pattern.
    fn build_test_polyvec() -> Polyvec {
        let mut pv = Polyvec::new();
        for (i, p) in pv.vec.iter_mut().enumerate() {
            for (j, c) in p.coeffs.iter_mut().enumerate() {
                // Pseudorandom-ish but deterministic. Keep coefficients
                // in [0, KYBER_Q) so the (>> 15 & Q) sign-correction
                // path is exercised on the negative side too.
                let v = ((i + 1) * 257 + j * 23) % (KYBER_Q + 100);
                *c = if j % 7 == 0 {
                    -(v as i16 % KYBER_Q as i16)
                } else {
                    v as i16 % KYBER_Q as i16
                };
            }
        }
        pv
    }

    /// The generic port must produce byte-identical output to the
    /// existing cfg-gated `polyvec_compress` for the current build's
    /// parameter set. Tested under kyber768 (default); the cfg-gated
    /// alternatives are validated when those features are selected.
    #[test]
    #[cfg(feature = "kyber768")]
    fn generic_matches_existing_kyber768() {
        use crate::MlKem768;

        let pv = build_test_polyvec();
        let mut buf_existing = [0u8; KYBER_POLYVEC_COMPRESSED_BYTES];
        polyvec_compress(&mut buf_existing, pv);

        let mut buf_generic =
            [0u8; polyvec_compressed_len::<MlKem768>()];
        polyvec_compress_generic::<MlKem768>(&mut buf_generic, &pv.vec);

        assert_eq!(
            buf_existing.as_slice(),
            buf_generic.as_slice(),
            "generic port diverges from existing polyvec_compress under \
             kyber768 — FIPS 203 compliance regression"
        );
    }

    #[test]
    #[cfg(feature = "kyber512")]
    fn generic_matches_existing_kyber512() {
        use crate::MlKem512;

        let pv = build_test_polyvec();
        let mut buf_existing = [0u8; KYBER_POLYVEC_COMPRESSED_BYTES];
        polyvec_compress(&mut buf_existing, pv);

        let mut buf_generic =
            [0u8; polyvec_compressed_len::<MlKem512>()];
        polyvec_compress_generic::<MlKem512>(&mut buf_generic, &pv.vec);

        assert_eq!(buf_existing.as_slice(), buf_generic.as_slice());
    }

    #[test]
    #[cfg(feature = "kyber1024")]
    fn generic_matches_existing_kyber1024() {
        use crate::MlKem1024;

        let pv = build_test_polyvec();
        let mut buf_existing = [0u8; KYBER_POLYVEC_COMPRESSED_BYTES];
        polyvec_compress(&mut buf_existing, pv);

        let mut buf_generic =
            [0u8; polyvec_compressed_len::<MlKem1024>()];
        polyvec_compress_generic::<MlKem1024>(
            &mut buf_generic,
            &pv.vec,
        );

        assert_eq!(buf_existing.as_slice(), buf_generic.as_slice());
    }

    /// Confirms the generic length helper matches FIPS 203 §6's
    /// `32 * K * DU` formula for all three parameter sets at compile
    /// time.
    #[test]
    fn compressed_length_formula() {
        use crate::{MlKem1024, MlKem512, MlKem768};
        assert_eq!(polyvec_compressed_len::<MlKem512>(), 32 * 2 * 10); // 640
        assert_eq!(polyvec_compressed_len::<MlKem768>(), 32 * 3 * 10); // 960
        assert_eq!(polyvec_compressed_len::<MlKem1024>(), 32 * 4 * 11); // 1408
    }
}

