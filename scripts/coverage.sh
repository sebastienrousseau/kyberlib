#!/usr/bin/env bash
# Coverage runner for kyberlib using cargo-llvm-cov.
#
# Why cargo-llvm-cov over tarpaulin:
#   - faster (single instrumented build instead of ptrace re-runs)
#   - more accurate for #[cfg(feature = ...)]-heavy crates (which
#     kyberlib is — security-level, 90s, avx2, nasm, hazmat …)
#   - emits LCOV + Cobertura + HTML in one pass
#   - integrates with codecov.io and GitHub PR annotations
#
# Run locally:
#   bash scripts/coverage.sh            # default — workspace, default features, HTML report
#   bash scripts/coverage.sh --ci       # LCOV output for codecov upload
#   bash scripts/coverage.sh --all-features
#
# Threshold gate:
#   COVERAGE_THRESHOLD=85 bash scripts/coverage.sh --ci
#
# CI invokes `bash scripts/coverage.sh --ci` and fails the build if
# line coverage drops below ${COVERAGE_THRESHOLD:-80}%.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

THRESHOLD="${COVERAGE_THRESHOLD:-80}"
MODE="local"
FEATURES_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --ci)            MODE="ci" ;;
        --all-features)  FEATURES_FLAG="--all-features" ;;
        --help|-h)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "ERROR: cargo-llvm-cov is not installed." >&2
    echo "Run: cargo install cargo-llvm-cov --locked" >&2
    exit 1
fi

OUT_DIR="target/coverage"
mkdir -p "$OUT_DIR"

echo ":: cargo llvm-cov clean"
cargo llvm-cov clean --workspace

# Single instrumented build pass covering:
#   - the workspace lib tests
#   - the integration tests under crates/kyberlib/tests/
#   - the new property + snapshot tests
#
# `--doctests` requires `-Z persist-doctests` which is nightly-only.
# We skip it on stable CI to keep the toolchain requirement loose;
# coverage gain from doctests is typically <5pp. Run with
# `+nightly` and `--doctests` locally for the full picture.
echo ":: cargo llvm-cov --workspace $FEATURES_FLAG"
cargo llvm-cov \
    --workspace \
    $FEATURES_FLAG \
    --no-fail-fast \
    --no-report \
    -- --test-threads=1

if [[ "$MODE" == "ci" ]]; then
    # CI mode: emit LCOV for codecov + Cobertura for GitHub PR
    # annotations, then enforce the threshold gate.
    cargo llvm-cov report --lcov      --output-path "$OUT_DIR/lcov.info"
    cargo llvm-cov report --cobertura --output-path "$OUT_DIR/cobertura.xml"
    cargo llvm-cov report --summary-only \
        --fail-under-lines "$THRESHOLD"

    echo ":: coverage artefacts in $OUT_DIR/"
    ls -la "$OUT_DIR/"
else
    # Local mode: HTML report for browser-based inspection.
    cargo llvm-cov report --html --output-dir "$OUT_DIR/html"
    cargo llvm-cov report --summary-only

    echo ":: HTML report — open $OUT_DIR/html/index.html"
fi
