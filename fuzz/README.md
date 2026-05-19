# kyberlib fuzz targets

cargo-fuzz / libFuzzer harness. Excluded from the main workspace because
it requires nightly + libFuzzer and adds ~50 transitive crates that we
do not want in normal builds.

## Setup

```sh
rustup install nightly
cargo install cargo-fuzz
```

## Targets

| Target          | What it fuzzes                                        | What must hold                                                  |
|-----------------|-------------------------------------------------------|-----------------------------------------------------------------|
| `fuzz_decap`    | `decapsulate(ct, sk)` with arbitrary inputs           | Never panics. FIPS 203 implicit rejection: always `Ok(_)` on lengths that match. |
| `fuzz_ct_parse` | Length validation of `ct` only (sk = zeros)           | Wrong-length ct → `Err(InvalidInput)` (never panic).            |
| `fuzz_pk_parse` | Length validation of `pk` in `encapsulate`            | Same — wrong-length pk → `Err(InvalidInput)`.                   |
| `fuzz_roundtrip`| Full gen → encap → decap with deterministic PRNG      | `ss_a == ss_b` always. Detects any non-deterministic branch.    |

## Running locally

```sh
# 60-second smoke against a single target
cd fuzz
cargo +nightly fuzz run fuzz_decap -- -runs=1000000

# Or via Makefile
make fuzz-smoke              # 10 seconds against fuzz_decap
make fuzz TARGET=fuzz_roundtrip
```

## Corpus

Seeds live under `fuzz/corpus/<target>/`. After a run, copy interesting
new inputs from `fuzz/artifacts/<target>/` back into the seed corpus
and commit them — they accelerate future runs and document the inputs
that exercised novel paths.

## Phase 4 integration

CI (#159):
- Per-PR: 10-second smoke run against `fuzz_decap` (non-blocking).
- Weekly: matrix of all four targets, each 1 hour, artifacts uploaded
  with 30-day retention.

## Limitations until Phase 2(b) lands

These targets exercise the **current Round-3** behaviour. Round-trip
agreement and length-validation invariants are spec-independent — they
hold for any IND-CCA KEM and so are valid fuzzing targets now. Once
the FIPS 203 patches land (the three changes documented in commit
`d6ded86`), the same targets continue to apply unchanged.
