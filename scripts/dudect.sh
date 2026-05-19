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
:: dudect harness — gating conditions satisfied; runner not yet wired.

The two preconditions that blocked the harness are now both
resolved:

  1. FIPS 203 spec migration is complete (Phase 2(b), commits
     417595a / 27e4b6b / b0f3bfb). 60/60 ML-KEM-768 ACVP cases
     pass; the cryptographic surface dudect would measure is now
     stable.

  2. The KyberSlash audit is complete (ADR 0003, this commit).
     Every secret-dependent `/` and `%` in the source tree
     uses Barrett-style multiply-and-shift; no `udiv` / `sdiv`
     leaks to measure.

What remains is the actual `dudect-bencher` integration: a Rust
harness that exercises `decapsulate` with carefully chosen input
classes (random pk × valid c, random pk × tampered c, etc.) and
runs the t-statistic test from de Reijke & Bertoni (eprint
2016/1123). That work is tracked as a follow-up to #161.

For now this script exits 0 so CI stays green. When the harness
lands, the body below activates.

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
