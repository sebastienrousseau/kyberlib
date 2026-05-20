use crate::params::KYBER_N;
use crate::poly::Poly;

/// Name:  load32_littleendian
///
/// Description: load 4 bytes into a 32-bit integer
///  in little-endian order
///
/// Arguments:   - const [u8] x: input byte array
///
/// Returns 32-bit unsigned integer loaded from x
fn load32_littleendian(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r |= (x[3] as u32) << 24;
    r
}

/// Name:  load32_littleendian
///
/// Description: load 3 bytes into a 32-bit integer
///  in little-endian order
///  This function is only needed for Kyber-512
///
/// Arguments:   - const [u8] x: input byte array
///
/// Returns 32-bit unsigned integer loaded from x
fn load24_littleendian(x: &[u8]) -> u32 {
    let mut r = x[0] as u32;
    r |= (x[1] as u32) << 8;
    r |= (x[2] as u32) << 16;
    r
}

/// Name:  cbd2
///
/// Description: Given an array of uniformly random bytes, compute
///  polynomial with coefficients distributed according to
///  a centered binomial distribution with parameter eta=2
///
/// Arguments:   - poly *r:    output polynomial
///  - const [u8] buf: input byte array
pub(crate) fn cbd2(r: &mut Poly, buf: &[u8]) {
    let (mut d, mut t, mut a, mut b);
    for i in 0..(KYBER_N / 8) {
        t = load32_littleendian(&buf[4 * i..]);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for j in 0..8 {
            a = ((d >> (4 * j)) & 0x3) as i16;
            b = ((d >> (4 * j + 2)) & 0x3) as i16;
            r.coeffs[8 * i + j] = a - b;
        }
    }
}

/// Name:  cbd3
///
/// Description: Given an array of uniformly random bytes, compute
///  polynomial with coefficients distributed according to
///  a centered binomial distribution with parameter eta=3
///  This function is only needed for Kyber-512
/// Arguments:   - poly *r:    output polynomial
///  - const [u8] buf: input byte array
pub(crate) fn cbd3(r: &mut Poly, buf: &[u8]) {
    let (mut d, mut t, mut a, mut b);
    for i in 0..(KYBER_N / 4) {
        t = load24_littleendian(&buf[3 * i..]);
        d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;
        for j in 0..4 {
            a = ((d >> (6 * j)) & 0x7) as i16;
            b = ((d >> (6 * j + 3)) & 0x7) as i16;
            r.coeffs[4 * i + j] = a - b;
        }
    }
}

pub(crate) fn poly_cbd_eta1(r: &mut Poly, buf: &[u8]) {
    if cfg!(feature = "kyber512") {
        cbd3(r, buf)
    } else {
        cbd2(r, buf)
    }
}

pub(crate) fn poly_cbd_eta2(r: &mut Poly, buf: &[u8]) {
    cbd2(r, buf)
}

// =============================================================================
// Generic ports over MlKemParams (#130b)
// =============================================================================

/// Generic port of [`poly_cbd_eta1`]. Selects cbd2 (η=2) vs cbd3 (η=3)
/// off `P::ETA1` rather than the cfg-feature global.
#[allow(dead_code)] // Wired incrementally; see #130c.
pub(crate) fn poly_cbd_eta1_generic<
    P: crate::paramsets::MlKemParams,
>(
    r: &mut Poly,
    buf: &[u8],
) {
    match P::ETA1 {
        2 => cbd2(r, buf),
        3 => cbd3(r, buf),
        _ => unreachable!("ETA1 must be 2 or 3 per FIPS 203 §6"),
    }
}

/// Generic port of [`poly_cbd_eta2`]. ETA2 is always 2 per FIPS 203,
/// so this is just a wrapper around `cbd2` parameterised at the type
/// level (kept symmetric with `poly_cbd_eta1_generic`).
#[allow(dead_code)]
pub(crate) fn poly_cbd_eta2_generic<
    P: crate::paramsets::MlKemParams,
>(
    r: &mut Poly,
    buf: &[u8],
) {
    debug_assert_eq!(P::ETA2, 2);
    cbd2(r, buf);
}

/// CBD buffer length for the ETA1 noise sampling under parameter `P`:
/// `P::ETA1 * 256 / 4` bytes.
#[allow(dead_code)]
pub(crate) const fn cbd_eta1_buf_len<
    P: crate::paramsets::MlKemParams,
>() -> usize {
    P::ETA1 * 256 / 4
}

/// CBD buffer length for the ETA2 noise sampling — always 128 bytes.
#[allow(dead_code)]
pub(crate) const fn cbd_eta2_buf_len<
    P: crate::paramsets::MlKemParams,
>() -> usize {
    P::ETA2 * 256 / 4
}

#[cfg(test)]
mod cbd_generic_tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;

    #[test]
    #[cfg(feature = "kyber768")]
    fn cbd_eta1_matches_existing_kyber768() {
        use crate::MlKem768;
        // ETA1 = 2 for MlKem768 → routes to cbd2.
        let buf = [0xA5u8; 128]; // 2 * 256 / 4 = 128
        let mut p_existing = Poly::new();
        poly_cbd_eta1(&mut p_existing, &buf);

        let mut p_generic = Poly::new();
        poly_cbd_eta1_generic::<MlKem768>(&mut p_generic, &buf);

        assert_eq!(p_existing.coeffs, p_generic.coeffs);
    }

    #[test]
    #[cfg(feature = "kyber512")]
    fn cbd_eta1_matches_existing_kyber512() {
        use crate::MlKem512;
        // ETA1 = 3 for MlKem512 → routes to cbd3.
        let buf = [0xA5u8; 192]; // 3 * 256 / 4 = 192
        let mut p_existing = Poly::new();
        poly_cbd_eta1(&mut p_existing, &buf);

        let mut p_generic = Poly::new();
        poly_cbd_eta1_generic::<MlKem512>(&mut p_generic, &buf);

        assert_eq!(p_existing.coeffs, p_generic.coeffs);
    }

    #[test]
    #[cfg(feature = "kyber1024")]
    fn cbd_eta1_matches_existing_kyber1024() {
        use crate::MlKem1024;
        let buf = [0xA5u8; 128];
        let mut p_existing = Poly::new();
        poly_cbd_eta1(&mut p_existing, &buf);

        let mut p_generic = Poly::new();
        poly_cbd_eta1_generic::<MlKem1024>(&mut p_generic, &buf);

        assert_eq!(p_existing.coeffs, p_generic.coeffs);
    }

    #[test]
    fn cbd_buf_lengths_match_spec() {
        use crate::{MlKem1024, MlKem512, MlKem768};
        // FIPS 203 §6: ETA1 × 256 / 4
        assert_eq!(cbd_eta1_buf_len::<MlKem512>(), 192); // η₁ = 3
        assert_eq!(cbd_eta1_buf_len::<MlKem768>(), 128); // η₁ = 2
        assert_eq!(cbd_eta1_buf_len::<MlKem1024>(), 128); // η₁ = 2
                                                          // ETA2 = 2 universally
        assert_eq!(cbd_eta2_buf_len::<MlKem512>(), 128);
        assert_eq!(cbd_eta2_buf_len::<MlKem768>(), 128);
        assert_eq!(cbd_eta2_buf_len::<MlKem1024>(), 128);
    }
}
