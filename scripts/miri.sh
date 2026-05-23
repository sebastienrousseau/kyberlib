#!/usr/bin/env bash
# Miri runner for kyberlib.
#
# `make miri` runs the focused subset suitable for per-PR CI gating.
# `make miri-full` (or `bash scripts/miri.sh full`) runs the full suite
# including the big-endian cross-target. The latter is slow — budget
# 30-90 minutes depending on the host.
#
# Miri detects undefined behaviour by interpreting Rust at the MIR
# level. It is the strongest non-formal correctness tool we have for
# detecting issues that bytewise testing misses (provenance violations,
# uninitialised reads, etc.).
#
# The AVX2 backend is excluded — Miri cannot interpret x86_64
# intrinsics. We rely on `cargo test` and the assembly's deterministic
# nature for that surface.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-focused}"

# Common flags. `-Zmiri-strict-provenance` enables the strictest
# Stacked-Borrows variant. `-Zmiri-disable-isolation` lets the
# harness read `tests/acvp/*.json` and other repo-relative files.
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation -Zmiri-strict-provenance}"

# Toolchain. Pin nightly via rust-toolchain.toml or pass via env.
TOOLCHAIN="${MIRI_TOOLCHAIN:-nightly}"

echo ":: rustup component add miri --toolchain $TOOLCHAIN"
rustup component add miri --toolchain "$TOOLCHAIN" 2>/dev/null || true
echo ":: cargo +$TOOLCHAIN miri setup"
cargo "+$TOOLCHAIN" miri setup >/dev/null

case "$MODE" in
    focused)
        echo ":: focused Miri subset (lib tests only, no-default-features)"
        # Cap test time and run the safe core only. AVX2 is excluded
        # via the absence of the avx2 feature.
        cargo "+$TOOLCHAIN" miri test \
            -p kyberlib \
            --no-default-features \
            --features kyber768 \
            --lib \
            -- --test-threads=1
        ;;
    full)
        echo ":: full Miri suite (lib + integration tests, no-default-features)"
        cargo "+$TOOLCHAIN" miri test \
            -p kyberlib \
            --no-default-features \
            --features kyber768 \
            -- --test-threads=1

        # Big-endian cross-target: catches endianness bugs in
        # serialisation paths. mips64-unknown-linux-gnuabi64 is big-endian.
        echo ":: big-endian sweep (mips64-unknown-linux-gnuabi64)"
        MIRI_TARGET=mips64-unknown-linux-gnuabi64 \
            cargo "+$TOOLCHAIN" miri test \
            -p kyberlib \
            --no-default-features \
            --features kyber768 \
            --lib \
            -- --test-threads=1
        ;;
    *)
        echo "Usage: $0 [focused|full]" >&2
        exit 1
        ;;
esac

echo ":: Miri OK ($MODE)"
