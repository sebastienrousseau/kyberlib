// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

extern crate criterion;

use criterion::{criterion_group, criterion_main, Criterion};
use kyberlib::{run, kyberlib_vec, kyberlib_map, kyberlib_join};

fn kyberlib_vec_benchmark(c: &mut Criterion) {
    c.bench_function("kyberlib_vec_macro", |b| {
        b.iter(|| {
            kyberlib_vec![1, 2, 3, 4, 5]
        })
    });
}

fn kyberlib_map_benchmark(c: &mut Criterion) {
    c.bench_function("kyberlib_map_macro", |b| {
        b.iter(|| {
            kyberlib_map!["a" => 1, "b" => 2, "c" => 3, "d" => 4, "e" => 5]
        })
    });
}

fn kyberlib_join_benchmark(c: &mut Criterion) {
    c.bench_function("kyberlib_join_macro", |b| {
        b.iter(|| {
            kyberlib_join!["a", "b", "c", "d", "e"]
        })
    });
}

fn kyberlib_benchmark(c: &mut Criterion) {
    c.bench_function("kyberlib", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                run().unwrap();
            }
        })
    });
}

criterion_group!(
    kyberlib_macros_benchmark,
    kyberlib_vec_benchmark,
    kyberlib_map_benchmark,
    kyberlib_join_benchmark,
    kyberlib_benchmark
);
criterion_main!(kyberlib_macros_benchmark);
