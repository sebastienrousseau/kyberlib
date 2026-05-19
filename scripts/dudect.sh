#!/usr/bin/env bash
# dudect-style constant-time analysis runner for kyberlib.
#
# `dudect` (de Reijke & Bertoni 2017, https://eprint.iacr.org/2016/1123)
# measures whether the timing distribution of a function differs
# significantly between two classes of inputs. A t-statistic above a
# threshold (typically ±4.5σ → ±10σ for very tight bounds) indicates
# secret-dependent timing.
#
# This script invokes the Rust harness in `crates/kyberlib/benches/dudect.rs`
# (added in Phase 4.3) which uses the `dudect-bencher` crate to run the
# statistical test. The harness is built but not run as part of the
# normal CI — execute manually before each release and on every change
# to the secret-handling paths.
#
# Status: **scaffolded only**. The Rust harness file lands as a
# placeholder until Phase 2(b) (FIPS 203 patch) closes the
# documented Round-3 vs FIPS-203 gaps. Running dudect against the
# current code would measure Round-3 behaviour and produce results
# that need re-running after the patches; the value of the gate
# comes after Phase 2(b).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Hard-fail threshold. Above this t-statistic we declare leakage.
# 10σ is the noyalib-aligned setting; 4.5σ is the original dudect
# default and is more sensitive but also more flake-prone on noisy
# CI runners.
T_THRESHOLD="${DUDECT_T_THRESHOLD:-10}"

cat <<'EOF'
:: dudect harness — currently a placeholder.

The full statistical CT harness is gated on Phase 2(b) (FIPS 203
patch) because:

  1. The current `decapsulate` path implements Kyber Round 3, not
     FIPS 203 ML-KEM. Running dudect against it would measure
     behaviour that is about to change.

  2. The KyberSlash audit (#149) replaces every secret-dependent
     `/` and `%` in `poly_compress` / `poly_tomsg` with Barrett-
     style multiplication. The dudect gate is meaningful only after
     that audit lands — beforehand it would either produce false
     positives (on the soon-to-be-fixed div instructions) or false
     negatives (because the broader Round-3 surface masks the
     specific lanes we want to measure).

  3. Phase 2(b) adds `tests/test_ct.rs` with deterministic input
     classes (random pk × valid c, random pk × tampered c, etc.)
     that the harness consumes.

To run when the harness lands:

    DUDECT_T_THRESHOLD=10 bash scripts/dudect.sh

Until then, this script exits 0 so CI does not break — the gate
flips on at the same time as the Phase 2(b) commits.

EOF

exit 0

# ---------------------------------------------------------------------
# Below is the *intended* runner. Activate when the harness lands.
# ---------------------------------------------------------------------
#
# cargo bench -p kyberlib --bench dudect -- \
#     --thresholds "$T_THRESHOLD" \
#     --samples 200000 \
#     --classes "valid_ct,tampered_ct,truncated_ct" \
#     --report json > dudect-report.json
#
# python3 scripts/dudect-summarise.py dudect-report.json
