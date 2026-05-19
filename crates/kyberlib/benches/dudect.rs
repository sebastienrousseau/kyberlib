// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Constant-time analysis harness for kyberlib using `dudect-bencher`.
//!
//! Background: de Reijke & Bertoni (eprint 2016/1123) — "dude, is my
//! code constant time?" — uses Welch's t-test on two timing
//! distributions to detect secret-dependent execution paths. Each
//! benchmark function below exercises a primitive under two input
//! *classes*; if the resulting timing distributions are statistically
//! indistinguishable, the function is plausibly constant-time under
//! the measurement conditions.
//!
//! ## Limits of dudect (and any black-box CT analysis)
//!
//! - **Negative result only** — passing means we *failed to detect* a
//!   leak, not that one provably doesn't exist. Pair with the formal
//!   audit in `doc/adr/0003-kyberslash-audit.md` and the structural
//!   Barrett-reduction guarantees inherited from pq-crystals.
//! - **Noise-bound** — runs on shared CI hosts are drowned in noise.
//!   For actionable signal, run on a quiescent baremetal host.
//! - **Timing only** — no cache, branch-predictor, or speculative
//!   side-channels.
//!
//! ## Classes covered
//!
//! 1. `decap_valid_vs_invalid_ct` — the IND-CCA workhorse. FIPS 203
//!    §6.3's implicit-rejection construction REQUIRES decapsulation of
//!    valid vs tampered ciphertext to take indistinguishable time. A
//!    t-statistic above ±10 here would be a CVE-class side-channel.
//!
//! 2. `decap_real_pairs` — decap a real (SK, matching CT) pair (Left)
//!    vs decap the same SK against the CT from a different real
//!    keypair (Right — implicit-rejection path on well-formed input).
//!    Confirms decap timing is invariant across both authentication
//!    outcomes when both inputs have the canonical shape produced by
//!    real keygen/encap. A leak here would indicate the FO transform
//!    branches observably on the validity check.
//!
//! ## Running
//!
//! Quick local check:
//! ```sh
//! cargo bench -p kyberlib --bench dudect --features benchmarking
//! ```
//!
//! Long run for release gating (see `scripts/dudect.sh`):
//! ```sh
//! cargo bench -p kyberlib --bench dudect --features benchmarking -- \
//!     --continuous decap_valid_vs_invalid_ct
//! ```

use dudect_bencher::{
    ctbench_main,
    rand::{Rng, RngExt},
    BenchRng, Class, CtRunner,
};
use kyberlib::{
    decapsulate, encapsulate, keypair, KYBER_CIPHERTEXT_BYTES,
    KYBER_SECRET_KEY_BYTES,
};

/// Per-class sample count. dudect's t-test stabilises around 10⁴–10⁵
/// samples per class; we default to 5k for a workable per-bench wall
/// clock (~30 s on a 2024-era laptop). The `scripts/dudect.sh`
/// production runner overrides with 1M.
const SAMPLES_PER_CLASS: usize = 5_000;

// =========================================================== rng bridge

/// `dudect_bencher::BenchRng` is a `rand 0.8` RNG, but kyberlib's
/// `keypair` / `encapsulate` consume `rand_core 0.6` RNGs. Bridge the
/// two with a thin wrapper. (Both crates' trait shapes are
/// byte-identical for the bytes we actually use.)
struct DudectRng<'a>(&'a mut BenchRng);

impl rand_core::RngCore for DudectRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.random()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.random()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for DudectRng<'_> {}

// =============================== bench 1: decap valid vs invalid ciphertext

/// **Headline CT-leak gate.** Decapsulate two ciphertext distributions
/// under the same secret key — one valid, one bit-flipped. FIPS 203
/// §6.3 implicit rejection REQUIRES indistinguishable timing.
fn decap_valid_vs_invalid_ct(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    // Single keygen — the secret-key half of the timing surface stays
    // fixed so the class signal isolates the ciphertext input.
    let keys = {
        let mut w = DudectRng(rng);
        keypair(&mut w).expect("setup keygen")
    };
    let valid_ct = {
        let mut w = DudectRng(rng);
        encapsulate(&keys.public, &mut w).expect("setup encap").0
    };

    let mut inputs: Vec<(Class, [u8; KYBER_CIPHERTEXT_BYTES])> =
        Vec::with_capacity(SAMPLES_PER_CLASS * 2);

    for _ in 0..SAMPLES_PER_CLASS * 2 {
        if rng.random::<bool>() {
            // Left class: untampered.
            inputs.push((Class::Left, valid_ct));
        } else {
            // Right class: flip a single random bit.
            let mut bad = valid_ct;
            let idx = (rng.random::<u32>() as usize)
                % KYBER_CIPHERTEXT_BYTES;
            let bit = (rng.random::<u32>() & 7) as u8;
            bad[idx] ^= 1u8 << bit;
            inputs.push((Class::Right, bad));
        }
    }

    for (class, ct) in inputs {
        runner.run_one(class, || {
            // Implicit rejection — always Ok with a pseudorandom SS
            // when the ciphertext is tampered.
            let _ss = decapsulate(&ct, &keys.secret);
        });
    }
}

// ============================== bench 2: decap of valid pair vs random pair

/// Decapsulate a real (SK, valid CT) pair (Left) vs decapsulate a
/// real SK against the corresponding ciphertext from an *unrelated*
/// real keypair (Right — implicit-rejection path on inputs of the
/// same shape as the legitimate ones).
///
/// Rationale: bench 1 stress-tests the same SK against valid vs
/// bit-flipped CT — the canonical IND-CCA test. Bench 2 generalises:
/// it confirms that decapsulation timing is invariant to which valid
/// (well-formed) ciphertext we're decapsulating, even when half of
/// them happen to authenticate and the other half don't. Both paths
/// must take the same time per FIPS 203 §6.3.
fn decap_real_pairs(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs: Vec<(Class, [u8; KYBER_SECRET_KEY_BYTES], [u8; KYBER_CIPHERTEXT_BYTES])> =
        Vec::with_capacity(SAMPLES_PER_CLASS * 2);

    for _ in 0..SAMPLES_PER_CLASS * 2 {
        // One real keypair (the "victim") and one decoy keypair per
        // sample. The decoy's ciphertext is only used in Right samples;
        // unconditional setup keeps the per-class setup work identical.
        let victim = {
            let mut w = DudectRng(rng);
            keypair(&mut w).expect("victim keygen")
        };
        let decoy = {
            let mut w = DudectRng(rng);
            keypair(&mut w).expect("decoy keygen")
        };
        let victim_ct = {
            let mut w = DudectRng(rng);
            encapsulate(&victim.public, &mut w).expect("victim encap").0
        };
        let decoy_ct = {
            let mut w = DudectRng(rng);
            encapsulate(&decoy.public, &mut w).expect("decoy encap").0
        };

        // Randomise class assignment per-sample per the upstream
        // dudect example pattern — avoids strict alternation creating
        // an artificial cache/branch-predictor signature.
        if rng.random::<bool>() {
            // Left: decap a legitimately-encapsulated CT — the
            // re-encryption check succeeds and the real SS is
            // selected.
            inputs.push((Class::Left, victim.secret, victim_ct));
        } else {
            // Right: decap a well-formed CT that wasn't encapsulated
            // to this PK — re-encryption mismatches and the
            // implicit-rejection path returns a pseudorandom SS.
            inputs.push((Class::Right, victim.secret, decoy_ct));
        }
    }

    for (class, sk, ct) in inputs {
        runner.run_one(class, || {
            let _ss = decapsulate(&ct, &sk);
        });
    }
}

// =========================================================== entry point

// Reproducible seeds across CI runs. dudect-bencher's macro doesn't
// accept a trailing comma — note the lack of one after the final entry.
ctbench_main!(decap_valid_vs_invalid_ct, decap_real_pairs);
