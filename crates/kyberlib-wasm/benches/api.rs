//! Native criterion benches for `kyberlib-wasm`.
//!
//! These run under host `cargo bench` — they measure the
//! Rust-side marshalling layer of `kyberlib-wasm`'s public API
//! (`keypair` / `encapsulate` / `decapsulate`) against the
//! equivalent calls in `kyberlib` core. The delta between the two
//! quantifies the cost of the `Box<[u8]>` heap allocation + the
//! getter copy-out that `wasm-bindgen` requires.
//!
//! Reproduction:
//!
//! ```sh
//! cargo bench -p kyberlib-wasm --bench api -- --quick --noplot
//! ```
//!
//! For a full criterion run (10 sample windows, HTML report) drop
//! the `--quick` flag.
//!
//! These benches do NOT measure the JS-side wasm-bindgen call cost
//! (browser context-switch, `Uint8Array` copy, etc.). For that, see
//! the planned `wasm-pack test --headless --bench` integration in
//! [#180](https://github.com/sebastienrousseau/kyberlib/issues/180).

use criterion::{
    black_box, criterion_group, criterion_main, Criterion,
};

fn bench_keypair(c: &mut Criterion) {
    let mut g = c.benchmark_group("kyberlib-wasm/marshalling");

    // Reference: the kyberlib core call without any boxing.
    g.bench_function("native/keypair", |b| {
        let mut rng = rand::rngs::OsRng;
        b.iter(|| {
            let keys = kyberlib::keypair(&mut rng).unwrap();
            black_box(keys);
        });
    });

    // The kyberlib-wasm wrapper. Same crypto + a `Box<[u8]>` heap
    // allocation and a `Keys` struct construction.
    g.bench_function("wasm/keypair", |b| {
        b.iter(|| {
            let keys = kyberlib_wasm::keypair().unwrap();
            black_box(keys);
        });
    });

    g.finish();
}

fn bench_encapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("kyberlib-wasm/marshalling");
    let keys = kyberlib_wasm::keypair().unwrap();
    let pk = keys.pubkey();

    g.bench_function("native/encapsulate", |b| {
        let mut rng = rand::rngs::OsRng;
        b.iter(|| {
            let kex = kyberlib::encapsulate(&pk, &mut rng).unwrap();
            black_box(kex);
        });
    });

    g.bench_function("wasm/encapsulate", |b| {
        b.iter(|| {
            let kex = kyberlib_wasm::encapsulate(pk.clone()).unwrap();
            black_box(kex);
        });
    });

    g.finish();
}

fn bench_decapsulate(c: &mut Criterion) {
    let mut g = c.benchmark_group("kyberlib-wasm/marshalling");

    let keys = kyberlib_wasm::keypair().unwrap();
    let pk = keys.pubkey();
    let sk = keys.secret();
    let exchange = kyberlib_wasm::encapsulate(pk).unwrap();
    let ct = exchange.ciphertext();

    g.bench_function("native/decapsulate", |b| {
        b.iter(|| {
            let ss = kyberlib::decapsulate(&ct, &sk).unwrap();
            black_box(ss);
        });
    });

    g.bench_function("wasm/decapsulate", |b| {
        b.iter(|| {
            let ss = kyberlib_wasm::decapsulate(ct.clone(), sk.clone())
                .unwrap();
            black_box(ss);
        });
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_keypair,
    bench_encapsulate,
    bench_decapsulate
);
criterion_main!(benches);
