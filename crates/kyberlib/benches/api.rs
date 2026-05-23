// Copyright © 2024-2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Criterion benchmarks for the kyberlib public API.
//!
//! Gated on `--features benchmarking` to keep the criterion dep out of
//! default `cargo bench` discovery on consumers' machines. Run with:
//!
//! ```sh
//! cargo bench -p kyberlib --features benchmarking
//! ```
//!
//! Every `b.iter` body wraps inputs and outputs in `criterion::black_box`
//! to prevent LLVM from constant-folding or DCE'ing the work — without
//! this, the timing numbers are unreliable for crypto primitives whose
//! inputs are constants known at compile time.
//!
//! Covers both the legacy free-function surface (`keypair`, `encapsulate`,
//! `decapsulate`) and the v0.0.7 typed-state surface (`MlKem768::generate`,
//! `EncapKey::encapsulate`, `DecapKey::decapsulate`).

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion,
    Throughput,
};
use kyberlib::{
    decapsulate, encapsulate, keypair, KemCore, MlKem768,
    KYBER_CIPHERTEXT_BYTES,
};
use rand::thread_rng;

// =================================================== legacy free-function API

fn bench_keypair(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("legacy/keypair", |b| {
        b.iter(|| {
            // black_box on the RngCore reference keeps LLVM from
            // proving the RNG is deterministic; black_box on the
            // return value defeats DCE on the produced bytes.
            let keys = keypair(black_box(&mut rng)).expect("keygen");
            black_box(keys);
        })
    });
}

fn bench_encapsulate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).expect("setup keygen");
    c.bench_function("legacy/encapsulate", |b| {
        b.iter(|| {
            let (ct, ss) = encapsulate(
                black_box(&keys.public),
                black_box(&mut rng),
            )
            .expect("encap");
            black_box(ct);
            black_box(ss);
        })
    });
}

fn bench_decapsulate_valid(c: &mut Criterion) {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).expect("setup keygen");
    let (ct, _ss) =
        encapsulate(&keys.public, &mut rng).expect("setup encap");
    c.bench_function("legacy/decapsulate/valid", |b| {
        b.iter(|| {
            let ss =
                decapsulate(black_box(&ct), black_box(&keys.secret))
                    .expect("decap");
            black_box(ss);
        })
    });
}

fn bench_decapsulate_invalid(c: &mut Criterion) {
    let mut rng = thread_rng();
    let keys = keypair(&mut rng).expect("setup keygen");
    // Construct an invalid ciphertext — must take the same time as a
    // valid one (FIPS 203 §6.3 implicit rejection). The bench result
    // delta is a coarse CT-leak signal; pair with `dudect` for the
    // statistically rigorous version.
    let bogus_ct = [0xA5u8; KYBER_CIPHERTEXT_BYTES];
    c.bench_function("legacy/decapsulate/invalid", |b| {
        b.iter(|| {
            // Implicit rejection — returns Ok with a pseudorandom SS.
            let ss = decapsulate(
                black_box(&bogus_ct),
                black_box(&keys.secret),
            )
            .expect("implicit rejection always Ok");
            black_box(ss);
        })
    });
}

// ================================================== v0.0.7 typed-state API

fn bench_typed_generate(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("typed/MlKem768::generate", |b| {
        b.iter(|| {
            let (dk, ek) = MlKem768::generate(black_box(&mut rng))
                .expect("keygen");
            black_box(dk);
            black_box(ek);
        })
    });
}

fn bench_typed_encapsulate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (_dk, ek) = MlKem768::generate(&mut rng).expect("setup keygen");
    c.bench_function("typed/EncapKey::encapsulate", |b| {
        b.iter(|| {
            let (ct, ss) =
                ek.encapsulate(black_box(&mut rng)).expect("encap");
            black_box(ct);
            black_box(ss);
        })
    });
}

fn bench_typed_decapsulate(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng).expect("setup keygen");
    let (ct, _ss) = ek.encapsulate(&mut rng).expect("setup encap");
    c.bench_function("typed/DecapKey::decapsulate", |b| {
        b.iter(|| {
            let ss = dk.decapsulate(black_box(&ct));
            black_box(ss);
        })
    });
}

// ============================================ end-to-end handshake throughput

fn bench_full_handshake(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut group = c.benchmark_group("handshake/MlKem768");
    // One handshake processes ~3.5 KB of key + ciphertext material.
    group.throughput(Throughput::Bytes(1184 + 1088));
    group.bench_function(BenchmarkId::from_parameter("full"), |b| {
        b.iter(|| {
            let (dk, ek) = MlKem768::generate(black_box(&mut rng))
                .expect("keygen");
            let (ct, ss_a) =
                ek.encapsulate(black_box(&mut rng)).expect("encap");
            let ss_b = dk.decapsulate(&ct);
            black_box((ss_a, ss_b));
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_keypair,
    bench_encapsulate,
    bench_decapsulate_valid,
    bench_decapsulate_invalid,
    bench_typed_generate,
    bench_typed_encapsulate,
    bench_typed_decapsulate,
    bench_full_handshake,
);
criterion_main!(benches);
