use crate::rng::randombytes;
use crate::{
    params::*, poly::*, polyvec::*, symmetric::*, CryptoRng,
    KyberLibError, RngCore,
};

#[cfg(feature = "hazmat")]
/// This module provides public constants related to the Kyber IND-CPA scheme.
pub use crate::params::{
    KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLIC_KEY_BYTES,
    KYBER_INDCPA_SECRET_KEY_BYTES,
};

/// Name:  pack_pk
///
/// Description: Serialize the public key as concatenation of the
///  serialized vector of polynomials pk
///  and the public seed used to generate the matrix A.
///
/// Arguments:   [u8] r:  the output serialized public key
///  const poly *pk:  the input public-key polynomial
///  const [u8] seed: the input public seed
fn pack_pk(r: &mut [u8], pk: &mut Polyvec, seed: &[u8]) {
    const END: usize = KYBER_SYM_BYTES + KYBER_POLYVEC_BYTES;
    polyvec_tobytes(r, pk);
    r[KYBER_POLYVEC_BYTES..END]
        .copy_from_slice(&seed[..KYBER_SYM_BYTES]);
}

/// Name:  unpack_pk
///
/// Description: De-serialize public key from a byte array;
///  approximate inverse of pack_pk
///
/// Arguments:   - Polyvec pk:  output public-key vector of polynomials
///  - [u8] seed:   output seed to generate matrix A
///  - const [u8] packedpk: input serialized public key
fn unpack_pk(pk: &mut Polyvec, seed: &mut [u8], packedpk: &[u8]) {
    const END: usize = KYBER_SYM_BYTES + KYBER_POLYVEC_BYTES;
    polyvec_frombytes(pk, packedpk);
    seed[..KYBER_SYM_BYTES]
        .copy_from_slice(&packedpk[KYBER_POLYVEC_BYTES..END]);
}

/// Name:  pack_sk
///
/// Description: Serialize the secret key
///
/// Arguments: - [u8] r:  output serialized secret key
///  - const Polyvec sk: input vector of polynomials (secret key)
fn pack_sk(r: &mut [u8], sk: &mut Polyvec) {
    polyvec_tobytes(r, sk);
}

/// Name:  unpack_sk
///
/// Description: De-serialize the secret key, inverse of pack_sk
///
/// Arguments:   - Polyvec sk: output vector of polynomials (secret key)
///  - const [u8] packedsk: input serialized secret key
fn unpack_sk(sk: &mut Polyvec, packedsk: &[u8]) {
    polyvec_frombytes(sk, packedsk);
}

/// Name:  pack_ciphertext
///
/// Description: Serialize the ciphertext as concatenation of the
///  compressed and serialized vector of polynomials b
///  and the compressed and serialized polynomial v
///
/// Arguments:   [u8] r:  the output serialized ciphertext
///  const poly *pk:  the input vector of polynomials b
///  const [u8] seed: the input polynomial v
fn pack_ciphertext(r: &mut [u8], b: &mut Polyvec, v: Poly) {
    polyvec_compress(r, *b);
    poly_compress(&mut r[KYBER_POLYVEC_COMPRESSED_BYTES..], v);
}

/// Name:  unpack_ciphertext
///
/// Description: De-serialize and decompress ciphertext from a byte array;
///  approximate inverse of pack_ciphertext
///
/// Arguments:   - Polyvec b:   output vector of polynomials b
///  - poly *v:  output polynomial v
///  - const [u8] c:   input serialized ciphertext
fn unpack_ciphertext(b: &mut Polyvec, v: &mut Poly, c: &[u8]) {
    polyvec_decompress(b, c);
    poly_decompress(v, &c[KYBER_POLYVEC_COMPRESSED_BYTES..]);
}

/// Name:  rej_uniform
///
/// Description: Run rejection sampling on uniform random bytes to generate
///  uniform random integers mod q
///
/// Arguments: - i16 *r:  output buffer
///  - usize len:   requested number of 16-bit integers (uniform mod q)
///  - const [u8] buf:  input buffer (assumed to be uniform random bytes)
///  - usize buflen:  length of input buffer in bytes
///
/// Returns number of sampled 16-bit integers (at most len)
fn rej_uniform(
    r: &mut [i16],
    len: usize,
    buf: &[u8],
    buflen: usize,
) -> usize {
    let (mut ctr, mut pos) = (0usize, 0usize);
    let (mut val0, mut val1);

    while ctr < len && pos + 3 <= buflen {
        val0 = (buf[pos] as u16 | (buf[pos + 1] as u16) << 8) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) as u16
            | (buf[pos + 2] as u16) << 4)
            & 0xFFF;
        pos += 3;

        if val0 < KYBER_Q as u16 {
            r[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < len && val1 < KYBER_Q as u16 {
            r[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

fn gen_a(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, false);
}

fn gen_at(a: &mut [Polyvec], b: &[u8]) {
    gen_matrix(a, b, true);
}

/// Name:  gen_matrix
///
/// Description: Deterministically generate matrix A (or the transpose of A)
///  from a seed. Entries of the matrix are polynomials that look
///  uniformly random. Performs rejection sampling on output of
///  a XOF
///
/// Arguments:   - Polyvec a: ouptput matrix A
///  - const [u8] seed: input seed
///  - bool transposed: boolean deciding whether A or A^T is generated
fn gen_matrix(a: &mut [Polyvec], seed: &[u8], transposed: bool) {
    let mut ctr;
    // 530 is expected number of required bytes
    // kyberslash-guard: safe — `const` expression evaluated at
    // compile time to size `buf`. No runtime division.  ADR 0003.
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES)
            / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut buflen: usize;
    let mut off: usize;
    let mut state = XofState::new();

    #[allow(clippy::needless_range_loop)]
    for i in 0..KYBER_SECURITY_PARAMETER {
        for j in 0..KYBER_SECURITY_PARAMETER {
            if transposed {
                xof_absorb(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb(&mut state, seed, j as u8, i as u8);
            }
            xof_squeezeblocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(
                &mut a[i].vec[j].coeffs,
                KYBER_N,
                &buf,
                buflen,
            );

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                xof_squeezeblocks(&mut buf[off..], 1, &mut state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(
                    &mut a[i].vec[j].coeffs[ctr..],
                    KYBER_N - ctr,
                    &buf,
                    buflen,
                );
            }
        }
    }
}

// Name:  indcpa_keypair
//
// Description: Generates public and private key for the CPA-secure
//  public-key encryption scheme underlying Kyber
//
// Arguments: - [u8] pk: output public key (length KYBER_INDCPA_PUBLIC_KEY_BYTES)
//  - [u8] sk: output private key (length KYBER_INDCPA_SECRET_KEY_BYTES)
pub(crate) fn indcpa_keypair<R>(
    pk: &mut [u8],
    sk: &mut [u8],
    _seed: Option<(&[u8], &[u8])>,
    _rng: &mut R,
) -> Result<(), KyberLibError>
where
    R: CryptoRng + RngCore,
{
    let mut a = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
    let (mut e, mut pkpv, mut skpv) =
        (Polyvec::new(), Polyvec::new(), Polyvec::new());
    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYM_BYTES];

    if let Some(s) = _seed {
        randbuf[..KYBER_SYM_BYTES].copy_from_slice(s.0);
    } else {
        randombytes(&mut randbuf, KYBER_SYM_BYTES, _rng)?;
    }

    // FIPS 203 §5.1 / §6.1 — `G(d || k_byte)` where `k_byte` is the
    // module rank (2 = ML-KEM-512, 3 = ML-KEM-768, 4 = ML-KEM-1024).
    // Kyber Round 3 used `G(d)` without the trailing byte; the byte
    // is the domain separator NIST added in the final standard.
    let mut g_input = [0u8; KYBER_SYM_BYTES + 1];
    g_input[..KYBER_SYM_BYTES]
        .copy_from_slice(&randbuf[..KYBER_SYM_BYTES]);
    g_input[KYBER_SYM_BYTES] = KYBER_SECURITY_PARAMETER as u8;
    hash_g(&mut buf, &g_input, KYBER_SYM_BYTES + 1);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYM_BYTES);
    gen_a(&mut a, publicseed);

    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_getnoise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_getnoise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    // matrix-vector multiplication
    #[allow(clippy::needless_range_loop)]
    for i in 0..KYBER_SECURITY_PARAMETER {
        polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], &a[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }
    polyvec_add(&mut pkpv, &e);
    polyvec_reduce(&mut pkpv);

    pack_sk(sk, &mut skpv);
    pack_pk(pk, &mut pkpv, publicseed);
    Ok(())
}

/// Name:  indcpa_enc
///
/// Description: Encryption function of the CPA-secure
///  public-key encryption scheme underlying Kyber.
///
/// Arguments:
///  - const [u8] c:    output ciphertext (length KYBER_INDCPA_BYTES)
///  - const [u8] m:    input message (length KYBER_SYM_BYTES)
///  - const [u8] pk:   input public key (length KYBER_INDCPA_PUBLIC_KEY_BYTES)
///  - const [u8] coin: input random coins used as seed (length KYBER_SYM_BYTES)
///    to deterministically generate all randomness
pub(crate) fn indcpa_enc(
    c: &mut [u8],
    m: &[u8],
    pk: &[u8],
    coins: &[u8],
) {
    let mut at = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
    let (mut sp, mut pkpv, mut ep, mut b) = (
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
        Polyvec::new(),
    );
    let (mut v, mut k, mut epp) =
        (Poly::new(), Poly::new(), Poly::new());
    let mut seed = [0u8; KYBER_SYM_BYTES];
    let mut nonce = 0u8;

    unpack_pk(&mut pkpv, &mut seed, pk);
    poly_frommsg(&mut k, m);
    gen_at(&mut at, &seed);

    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_getnoise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }
    for i in 0..KYBER_SECURITY_PARAMETER {
        poly_getnoise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }
    poly_getnoise_eta2(&mut epp, coins, nonce);

    polyvec_ntt(&mut sp);

    // matrix-vector multiplication
    #[allow(clippy::needless_range_loop)]
    for i in 0..KYBER_SECURITY_PARAMETER {
        polyvec_basemul_acc_montgomery(&mut b.vec[i], &at[i], &sp);
    }

    polyvec_basemul_acc_montgomery(&mut v, &pkpv, &sp);
    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext(c, &mut b, v);
}

/// Name:  indcpa_dec
///
/// Description: Decryption function of the CPA-secure
///  public-key encryption scheme underlying Kyber.
///
/// Arguments:
///  - const [u8] m:    output decrypted message (of length KYBER_SYM_BYTES)
///  - const [u8] c:    input ciphertext (of length KYBER_INDCPA_BYTES)
///  - const [u8] sk:   input secret key (of length KYBER_INDCPA_SECRET_KEY_BYTES)
pub(crate) fn indcpa_dec(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let (mut b, mut skpv) = (Polyvec::new(), Polyvec::new());
    let (mut v, mut mp) = (Poly::new(), Poly::new());

    unpack_ciphertext(&mut b, &mut v, c);
    unpack_sk(&mut skpv, sk);

    polyvec_ntt(&mut b);
    polyvec_basemul_acc_montgomery(&mut mp, &skpv, &b);
    poly_invntt_tomont(&mut mp);

    poly_sub(&mut mp, &v);
    poly_reduce(&mut mp);

    poly_tomsg(m, mp);
}

// =============================================================================
// Generic ports over MlKemParams (#130b — integration layer)
// =============================================================================
//
// Strategy: take polyvec and matrix workspaces as `&mut [Poly]` slices.
// The caller allocates a flat buffer of size `K*K` for the matrix and
// `K` for each polyvec. Inside, indices are computed as `i * P::K + j`
// for matrix accesses. This sidesteps the stable-Rust `[T; K*K]`
// restriction and avoids `alloc`.

/// Generic port of [`gen_matrix`].
///
/// `a` is a flat slice of `P::K * P::K` polynomials laid out
/// row-major: `a[i * P::K + j]` is the (i,j)-th entry of the matrix
/// (or its transpose if `transposed`).
#[allow(dead_code)]
pub(crate) fn gen_matrix_generic<P: crate::paramsets::MlKemParams>(
    a: &mut [Poly],
    seed: &[u8],
    transposed: bool,
) {
    debug_assert_eq!(a.len(), P::K * P::K);

    let mut ctr;
    // kyberslash-guard: safe — compile-time const expression sizes buf.
    const GEN_MATRIX_NBLOCKS: usize =
        (12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES)
            / XOF_BLOCKBYTES;
    let mut buf = [0u8; GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    let mut buflen: usize;
    let mut off: usize;
    let mut state = XofState::new();

    for i in 0..P::K {
        for j in 0..P::K {
            if transposed {
                xof_absorb(&mut state, seed, i as u8, j as u8);
            } else {
                xof_absorb(&mut state, seed, j as u8, i as u8);
            }
            xof_squeezeblocks(&mut buf, GEN_MATRIX_NBLOCKS, &mut state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(
                &mut a[i * P::K + j].coeffs,
                KYBER_N,
                &buf,
                buflen,
            );

            while ctr < KYBER_N {
                off = buflen % 3;
                for k in 0..off {
                    buf[k] = buf[buflen - off + k];
                }
                xof_squeezeblocks(&mut buf[off..], 1, &mut state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform(
                    &mut a[i * P::K + j].coeffs[ctr..],
                    KYBER_N - ctr,
                    &buf,
                    buflen,
                );
            }
        }
    }
}

/// Maximum module rank across all FIPS 203 parameter sets. Used to
/// size stack workspaces in the generic indcpa primitives below.
const MAX_K: usize = 4;

/// Generic port of [`indcpa_keypair`]. Drives all per-set work off
/// `P: MlKemParams` — uses fixed `MAX_K`-sized stack workspaces and
/// only the first `P::K` slots, sidestepping stable Rust's
/// `[T; P::K]` restriction.
///
/// Stack usage: ~14 KB (matrix `[Poly; 16]` + 3 polyvecs of
/// `[Poly; 4]`). Acceptable for non-embedded; embedded consumers
/// stay on the cfg-gated path.
#[allow(dead_code, clippy::needless_range_loop)]
pub(crate) fn indcpa_keypair_generic<P, R>(
    pk: &mut [u8],
    sk: &mut [u8],
    seed: Option<(&[u8], &[u8])>,
    rng: &mut R,
) -> Result<(), KyberLibError>
where
    P: crate::paramsets::MlKemParams,
    R: CryptoRng + RngCore,
{
    debug_assert!(P::K <= MAX_K);

    // Workspaces. MAX_K-sized so the array dims are concrete `usize`.
    let mut a = [Poly::new(); MAX_K * MAX_K];
    let mut skpv = [Poly::new(); MAX_K];
    let mut pkpv = [Poly::new(); MAX_K];
    let mut e = [Poly::new(); MAX_K];

    let mut nonce = 0u8;
    let mut buf = [0u8; 2 * KYBER_SYM_BYTES];
    let mut randbuf = [0u8; 2 * KYBER_SYM_BYTES];

    if let Some(s) = seed {
        randbuf[..KYBER_SYM_BYTES].copy_from_slice(s.0);
    } else {
        randombytes(&mut randbuf, KYBER_SYM_BYTES, rng)?;
    }

    // FIPS 203 §5.1 / §6.1: G(d || k_byte). k_byte = P::K.
    let mut g_input = [0u8; KYBER_SYM_BYTES + 1];
    g_input[..KYBER_SYM_BYTES]
        .copy_from_slice(&randbuf[..KYBER_SYM_BYTES]);
    g_input[KYBER_SYM_BYTES] = P::K as u8;
    hash_g(&mut buf, &g_input, KYBER_SYM_BYTES + 1);

    let (publicseed, noiseseed) = buf.split_at(KYBER_SYM_BYTES);

    // Use only the first K*K entries of the matrix workspace.
    gen_matrix_generic::<P>(&mut a[..P::K * P::K], publicseed, false);

    // Sample skpv, e — only the first K slots.
    for i in 0..P::K {
        // `poly_getnoise_eta1` calls `prf` with a ETA1-dependent buffer
        // length. The buffer it needs is computed inside that function
        // using the global KYBER_ETA1 constant. For a true generic port
        // we'd need `poly_getnoise_eta1_generic<P>` calling
        // `poly_cbd_eta1_generic<P>`. Phase 3d follow-up — for now this
        // function compiles but produces output specialized to the
        // active build's KYBER_ETA1, so it only validates against the
        // existing `indcpa_keypair` under that same build.
        poly_getnoise_eta1(&mut skpv[i], noiseseed, nonce);
        nonce += 1;
    }
    for i in 0..P::K {
        poly_getnoise_eta1(&mut e[i], noiseseed, nonce);
        nonce += 1;
    }

    polyvec_ntt_generic::<P>(&mut skpv[..P::K]);
    polyvec_ntt_generic::<P>(&mut e[..P::K]);

    // pkpv[i] = A[i] · skpv  (matrix-vector multiplication)
    for i in 0..P::K {
        let row_start = i * P::K;
        let row_end = row_start + P::K;
        polyvec_basemul_acc_montgomery_generic::<P>(
            &mut pkpv[i],
            &a[row_start..row_end],
            &skpv[..P::K],
        );
        poly_tomont(&mut pkpv[i]);
    }
    polyvec_add_generic::<P>(&mut pkpv[..P::K], &e[..P::K]);
    polyvec_reduce_generic::<P>(&mut pkpv[..P::K]);

    // pack_sk: just polyvec_tobytes
    polyvec_tobytes_generic::<P>(sk, &skpv[..P::K]);

    // pack_pk: polyvec_tobytes(pk) || publicseed
    polyvec_tobytes_generic::<P>(
        &mut pk[..polyvec_bytes_len::<P>()],
        &pkpv[..P::K],
    );
    pk[polyvec_bytes_len::<P>()
        ..polyvec_bytes_len::<P>() + KYBER_SYM_BYTES]
        .copy_from_slice(&publicseed[..KYBER_SYM_BYTES]);

    Ok(())
}

#[cfg(test)]
mod indcpa_generic_tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;

    /// gen_matrix_generic must produce the same matrix as the existing
    /// gen_matrix under the active feature.
    #[test]
    #[cfg(feature = "kyber768")]
    fn gen_matrix_matches_existing_kyber768() {
        use crate::MlKem768;
        let seed = [0xA5u8; KYBER_SYM_BYTES];

        // Existing path: [Polyvec; KYBER_SECURITY_PARAMETER]
        let mut a_existing = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
        gen_matrix(&mut a_existing, &seed, false);

        // Generic path: flat [Poly; K*K] = 9 for K=3
        let mut a_generic = [Poly::new(); 9];
        gen_matrix_generic::<MlKem768>(&mut a_generic, &seed, false);

        // Compare row-major: a_existing[i].vec[j] vs a_generic[i*K + j]
        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(
                    a_existing[i].vec[j].coeffs,
                    a_generic[i * 3 + j].coeffs,
                    "matrix entry ({i},{j}) diverges"
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "kyber768")]
    fn gen_matrix_transposed_matches_existing_kyber768() {
        use crate::MlKem768;
        let seed = [0xC3u8; KYBER_SYM_BYTES];

        let mut a_existing = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
        gen_matrix(&mut a_existing, &seed, true);

        let mut a_generic = [Poly::new(); 9];
        gen_matrix_generic::<MlKem768>(&mut a_generic, &seed, true);

        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(
                    a_existing[i].vec[j].coeffs,
                    a_generic[i * 3 + j].coeffs
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "kyber512")]
    fn gen_matrix_matches_existing_kyber512() {
        use crate::MlKem512;
        let seed = [0xA5u8; KYBER_SYM_BYTES];
        let mut a_existing = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
        gen_matrix(&mut a_existing, &seed, false);

        let mut a_generic = [Poly::new(); 4]; // K=2, K*K=4
        gen_matrix_generic::<MlKem512>(&mut a_generic, &seed, false);

        for i in 0..2 {
            for j in 0..2 {
                assert_eq!(
                    a_existing[i].vec[j].coeffs,
                    a_generic[i * 2 + j].coeffs
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "kyber1024")]
    fn gen_matrix_matches_existing_kyber1024() {
        use crate::MlKem1024;
        let seed = [0xA5u8; KYBER_SYM_BYTES];
        let mut a_existing = [Polyvec::new(); KYBER_SECURITY_PARAMETER];
        gen_matrix(&mut a_existing, &seed, false);

        let mut a_generic = [Poly::new(); 16]; // K=4, K*K=16
        gen_matrix_generic::<MlKem1024>(&mut a_generic, &seed, false);

        for i in 0..4 {
            for j in 0..4 {
                assert_eq!(
                    a_existing[i].vec[j].coeffs,
                    a_generic[i * 4 + j].coeffs
                );
            }
        }
    }
}

#[cfg(test)]
mod indcpa_integration_tests {
    #![allow(unused_imports)]
    use super::*;
    use crate::paramsets::MlKemParams;

    /// **The headline integration test**: indcpa_keypair_generic
    /// driven from a fixed seed must produce byte-identical (pk, sk)
    /// to the existing cfg-gated indcpa_keypair.
    #[test]
    #[cfg(feature = "kyber768")]
    fn indcpa_keypair_generic_matches_existing_kyber768() {
        use crate::MlKem768;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let seed = [0x77u8; 64];

        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut pk_existing = [0u8; KYBER_INDCPA_PUBLIC_KEY_BYTES];
        let mut sk_existing = [0u8; KYBER_INDCPA_SECRET_KEY_BYTES];
        indcpa_keypair(
            &mut pk_existing,
            &mut sk_existing,
            Some((&seed[..32], &seed[32..])),
            &mut rng,
        )
        .unwrap();

        let mut rng2 = StdRng::from_seed([0u8; 32]);
        let mut pk_generic = [0u8; KYBER_INDCPA_PUBLIC_KEY_BYTES];
        let mut sk_generic = [0u8; KYBER_INDCPA_SECRET_KEY_BYTES];
        indcpa_keypair_generic::<MlKem768, _>(
            &mut pk_generic,
            &mut sk_generic,
            Some((&seed[..32], &seed[32..])),
            &mut rng2,
        )
        .unwrap();

        assert_eq!(
            pk_existing.as_slice(),
            pk_generic.as_slice(),
            "indcpa_keypair_generic pk diverges from existing — \
             FIPS 203 compliance regression in the generic port"
        );
        assert_eq!(
            sk_existing.as_slice(),
            sk_generic.as_slice(),
            "indcpa_keypair_generic sk diverges from existing"
        );
    }
}
