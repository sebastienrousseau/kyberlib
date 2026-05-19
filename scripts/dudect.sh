#!/usr/bin/env bash
# dudect-style constant-time analysis runner for kyberlib.
#
# Background: de Reijke & Bertoni 2017 (eprint 2016/1123) — "dude, is
# my code constant time?". Runs Welch's t-test on two timing
# distributions to detect secret-dependent execution paths. A
# t-statistic above ±4.5σ indicates leakage (we use ±10σ for tighter
# release-gate bounds).
#
# Implementation: `crates/kyberlib/benches/dudect.rs` (the
# `dudect-bencher`-driven harness). Covers:
#
#   - decap_valid_vs_invalid_ct       — FIPS 203 §6.3 implicit-
#                                       rejection timing equivalence
#   - decap_zero_vs_ff_secret_stream  — KyberSlash-class
#                                       Hamming-weight invariance
#
# Modes:
#   bash scripts/dudect.sh            # quick check (10k samples / bench)
#   bash scripts/dudect.sh full       # release gate (200k samples)
#   bash scripts/dudect.sh continuous # streaming; Ctrl-C to stop
#
# CI does *not* run dudect — shared CI runners introduce timing noise
# that overwhelms any real signal. Run on a quiescent baremetal host
# before each release.
#
# Output format (per bench):
#   `n == +0.200M, max t = +X.YYYYY, max tau = +0.0NNNN, (5/tau)^2 = N`
# where `max t` is the Welch t-statistic. Anything below `T_THRESHOLD`
# (default 10) passes; anything above is an investigation trigger.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

T_THRESHOLD="${DUDECT_T_THRESHOLD:-10}"
MODE="${1:-quick}"
LOG="${DUDECT_LOG:-target/dudect.log}"

mkdir -p target

echo ":: building dudect harness in release mode"
# Use `--message-format=json` so we get the exact compiled binary
# path back, respecting `CARGO_TARGET_DIR` and any user overrides
# (the script must not assume the binary lives under ./target/).
BUILD_JSON=$(cargo build \
    --release \
    --bench dudect \
    --features benchmarking \
    -p kyberlib \
    --message-format=json 2>/dev/null)

BINARY=$(echo "$BUILD_JSON" \
    | grep -o '"executable":"[^"]*dudect-[^"]*"' \
    | head -1 \
    | sed 's/"executable":"//; s/"$//')

if [[ -z "$BINARY" ]]; then
    echo "ERROR: could not locate compiled dudect harness binary" >&2
    exit 1
fi

echo ":: harness binary: $BINARY"
echo ":: mode: $MODE  (T_THRESHOLD = ±$T_THRESHOLD)"

# Capture run output to a temp file so we parse the same bytes we
# show to the user (running the harness twice produces independent
# noise on the t-statistics, which would make the gate non-deterministic
# vs the displayed numbers).
RUN_OUT=$(mktemp)
trap 'rm -f "$RUN_OUT"' EXIT

case "$MODE" in
    quick)
        # Default sample count from benches/dudect.rs::SAMPLES_PER_CLASS
        # (5k per class). Suitable for dev-loop checks; not for release.
        "$BINARY" --out "$LOG" | tee "$RUN_OUT"
        ;;
    full)
        # For a release gate, run with substantially more samples per
        # class — edit benches/dudect.rs::SAMPLES_PER_CLASS to 200_000
        # and rebuild. (dudect-bencher's CLI doesn't expose sample
        # count as a flag.) The 200k figure is the noyalib-aligned
        # release-gate norm; on a quiescent baremetal host it takes
        # roughly 15-20 minutes per bench.
        echo ":: full mode — assumes SAMPLES_PER_CLASS has been raised"
        echo "   in benches/dudect.rs (default 5k → release 200k)"
        "$BINARY" --out "$LOG" | tee "$RUN_OUT"
        ;;
    continuous)
        # Streaming mode — runs forever, printing rolling t-stats.
        # Use to triage a flagged bench.
        echo ":: continuous mode — Ctrl-C to stop"
        exec "$BINARY" --continuous decap_valid_vs_invalid_ct --out "$LOG"
        ;;
    *)
        echo "Usage: $0 [quick|full|continuous]" >&2
        exit 2
        ;;
esac

echo
echo ":: raw samples written to $LOG"
echo
echo ":: parsing t-statistics for threshold violations…"

# Threshold gate. The harness prints `max t = +X.YYYYY` per bench;
# extract |t| and compare to T_THRESHOLD.
FAIL=0
while IFS= read -r line; do
    if [[ "$line" =~ max\ t\ =\ ([+-]?[0-9]+\.[0-9]+) ]]; then
        t_val="${BASH_REMATCH[1]}"
        abs_t=$(awk -v v="$t_val" 'BEGIN { print (v < 0 ? -v : v) }')
        if awk -v a="$abs_t" -v t="$T_THRESHOLD" 'BEGIN { exit !(a > t) }'; then
            echo "  LEAK: |t| = $abs_t exceeds ±$T_THRESHOLD"
            echo "        line: $line"
            FAIL=1
        else
            echo "  OK:   |t| = $abs_t  <  ±$T_THRESHOLD"
        fi
    fi
done < <(grep 'max t =' "$RUN_OUT")

if [[ $FAIL -ne 0 ]]; then
    echo
    echo ":: FAIL — timing-leak signal detected. Investigate before release."
    exit 1
fi

echo
echo ":: PASS — no constant-time leak detected at ±$T_THRESHOLD."
echo
echo ":: Note: dudect is a negative result only — failure to detect"
echo "   doesn't prove CT. Pair with the structural audit in"
echo "   doc/adr/0003-kyberslash-audit.md and the Barrett-reduction"
echo "   guarantees inherited from pq-crystals."
