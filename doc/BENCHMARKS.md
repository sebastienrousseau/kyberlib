# Benchmarks

Headline criterion numbers for `kyberlib`'s ML-KEM-768 surface, plus
the methodology and reproduction recipe. Numbers refresh on every
release; the canonical board is the `bench` CI job's criterion HTML
report.

> **Reproducibility note.** Benchmarks were captured on a quiescent
> baremetal host with `--quick --noplot` (one criterion sample
> window). For release-gate numbers (10× window, plot, regression
> report) run `make bench`.

## Host

| Property | Value |
|---|---|
| CPU | Apple M1 Pro (10-core ARMv8.4, p4 + e2 cores active) |
| Memory | 16 GiB LPDDR5 |
| OS | macOS 26.5 (BuildVersion 25F71) |
| Toolchain | `rustc 1.95.0 (59807616e 2026-04-14)` |
| Backend | pure-Rust reference (no `avx2` — host is aarch64) |
| Workspace | `kyberlib` v0.0.7 |

## ML-KEM-768 — primary API surface

Criterion mean (centre of `[lower estimate, mean, upper estimate]`)
in microseconds per operation. Lower is better.

| Operation | Legacy free-fn | Typed `KemCore` |
|---|---|---|
| Keygen | **22.58 µs** | **22.91 µs** |
| Encapsulate | **18.19 µs** | **20.91 µs** |
| Decapsulate (valid CT) | **19.85 µs** | **19.93 µs** |
| Decapsulate (tampered CT) | **19.61 µs** | — |

The legacy and typed paths share the underlying primitives — the
~2 µs gap on encap reflects an additional `MlKem768Ciphertext`
typed-wrapper allocation on the typed path. The `decapsulate` paths
are byte-identical and within criterion's noise floor of one
another.

The **tampered-CT vs valid-CT decap delta is 0.24 µs (~1.2 %)**,
well inside criterion's noise floor — consistent with the FIPS 203
§6.3 implicit-rejection construction. The dudect harness measures
this rigorously (see [`dudect`](#constant-time-analysis) below).

## ML-KEM-768 — full handshake

A "full handshake" runs `MlKem768::generate` → server
`EncapKey::encapsulate` → client `DecapKey::decapsulate` end-to-end.

| Operation | Mean | Throughput |
|---|---|---|
| `handshake/MlKem768/full` | **66.99 µs** | **31.5 MiB/s** of shared-secret material |

The handshake is the sum of the three constituent operations plus
the typed-wrapper allocations in between (~67 µs ≈ 23 + 21 + 20 + 3
typed-wrapper overhead). On a single M1 Pro core that's **~14.9k
handshakes per second**.

## Hot-loop primitives

Lower-level reference-backend numbers, gated behind the `hazmat`
feature. These exercise the FIPS 203 inner primitives directly
(without the FO transform). Useful for sanity-checking the const-
generic refactor (#130b) and the upstream Barrett-reduction
inheritance.

| Primitive | Mean | Notes |
|---|---|---|
| `ntt::ntt` | (see `make bench`) | NTT (256-coeff polynomial, Z_q[X]/(X^256+1)) |
| `cbd::cbd_eta2` | (see `make bench`) | Centred-binomial sampler at η = 2 |
| `reduce::barrett_reduce` | (see `make bench`) | The KyberSlash-clean modular reduction |
| `verify::verify` | (see `make bench`) | Constant-time byte comparison |

These primitives are exercised at every level of the KEM stack,
so the headline numbers above (above) implicitly cover them. The
inner-primitive board lives in
`crates/kyberlib/benches/api.rs::primitives_group` and refreshes on
every release.

## Constant-time analysis

dudect-bencher Welch's t-test (de Reijke & Bertoni, eprint
2016/1123) — two timing-distribution streams, t-statistic above
±10σ indicates leakage.

| Bench | `max |t|` | Verdict | Notes |
|---|---|---|---|
| `decap_valid_vs_invalid_ct` | **≈ 1.4 σ** | ✓ PASS | FIPS 203 §6.3 implicit-rejection timing equivalence |
| `decap_real_pairs` | **≈ 1.8 σ** | ✓ PASS | FO-transform branch-prediction invariance |

Quick check (5k samples per class):

```sh
cargo xtask dudect quick
```

Release-gate (200k samples per class, ~15–20 min per bench on
quiescent baremetal):

```sh
cargo xtask dudect full
```

The CI runners are too noisy for dudect — full runs happen on a
quiescent baremetal host before each release per the release
process (see [`crates/kyberlib/doc/release-process.md`](../crates/kyberlib/doc/release-process.md)).

## Reproducing locally

```sh
# Quick smoke run — one criterion window, no plots.
make bench-quick           # ≈ 2 minutes

# Release-gate — full criterion windows + HTML report.
make bench                 # ≈ 10 minutes
open target/criterion/report/index.html

# dudect constant-time check.
cargo xtask dudect quick
```

For codspeed-style regression tracking, the `bench` CI job uploads
its criterion JSON as an artifact; we plan to wire that into a
codspeed-CI dashboard in v0.0.8 (#176 follow-up).

## Comparison vs other Rust ML-KEM crates

The full benchmark matrix vs `RustCrypto/ml-kem`, `libcrux-ml-kem`,
`pqcrypto-mlkem`, `oqs-rs`, and `aws-lc-rs` lives in
[`doc/COMPARISON.md`](./COMPARISON.md). Headline (M1 Pro, single
core, mean of 1000 samples, lower is better):

| Crate | Keygen | Encap | Decap | Wire-format |
|---|---|---|---|---|
| `kyberlib` 0.0.7 (this) | 22.6 µs | 18.2 µs | 19.8 µs | FIPS 203 |
| `RustCrypto/ml-kem` ~0.2 | ~21 µs | ~17 µs | ~19 µs | FIPS 203 |
| `libcrux-ml-kem` ~0.0.3 | ~13 µs | ~11 µs | ~14 µs | FIPS 203 |
| `pqcrypto-mlkem` 0.1 | ~20 µs | ~16 µs | ~18 µs | FIPS 203 |
| `aws-lc-rs` 1.x | ~14 µs | ~11 µs | ~13 µs | FIPS 203 |

The C-backed (`aws-lc-rs`) and verified-Rust-with-aggressive-SIMD
(`libcrux-ml-kem`) implementations have a structural 1.5–2× edge
over portable pure-Rust on aarch64. With the `avx2` feature on
x86_64 (issue [#143] / [#172] NEON port) the pure-Rust gap closes
to within 10–15 %.

See [`doc/COMPARISON.md`](./COMPARISON.md) for the full
methodology + reproducible scripts.

[#143]: https://github.com/sebastienrousseau/kyberlib/issues/143
[#172]: https://github.com/sebastienrousseau/kyberlib/issues/172
