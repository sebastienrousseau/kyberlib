#!/usr/bin/env bash
# KyberSlash regression guard.
#
# Greps the kyberlib source tree for `/` and `%` operations against
# `KYBER_Q` — the pattern that produced the KyberSlash class of
# timing side-channels (eprint 2023/1933, TCHES 2025). The current
# code uses Barrett-style multiply-and-shift instead; this script
# fails CI if anyone reintroduces a literal division.
#
# Lines explicitly annotated with a comment that contains
# `kyberslash-guard: safe` IMMEDIATELY ABOVE the offending line are
# exempt — these are constant-folded sites with no secret input.
# Each annotation should cite ADR 0003 and explain why the site is
# safe. The guard's job is to surface NEW occurrences for a fresh
# decision.
#
# Reference: doc/adr/0003-kyberslash-audit.md
#
# Run with:
#   bash scripts/kyberslash-guard.sh
#
# Wired into Makefile as `make kyberslash-guard`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Forbidden patterns. Each is an extended regex.
#
# The two leading-operator forms cover every variant we care about
# because `\bKYBER_Q\b` matches `KYBER_Q` regardless of whether it's
# preceded by `(`, ` `, `\t`, `<<`, etc. — and that's the half that
# isn't filtered out by the comment-stripping pass.
declare -a PATTERNS=(
    '/[[:space:]]*KYBER_Q\b'
    '%[[:space:]]*KYBER_Q\b'
)

declare -a FILES
mapfile -t FILES < <(find crates/kyberlib/src -name '*.rs' -type f)

VIOLATIONS=0

# Per-file linear scan in awk:
#  - track whether the most recent comment line carried
#    `kyberslash-guard: safe`,
#  - skip pure-comment lines (`//` or `/// ` or `* `) from the
#    forbidden-pattern check (the ADR + this script's own header
#    legitimately reference the pattern in prose),
#  - for any non-comment line matching the pattern AND not preceded
#    by a safe-marker comment line, emit a violation.
#
# `safe_armed` resets to 0 on any non-comment line so the marker
# only protects the *immediately following* code line.
scan_file() {
    local file="$1"
    local pattern="$2"

    awk -v pat="$pattern" -v file="$file" '
        BEGIN { safe_armed = 0; violations = 0 }
        {
            # Strip leading whitespace for classification.
            stripped = $0
            sub(/^[[:space:]]+/, "", stripped)

            if (stripped ~ /^\/\// || stripped ~ /^\*/) {
                # Comment line. Check for the marker.
                if ($0 ~ /kyberslash-guard:[[:space:]]*safe/) {
                    safe_armed = 1
                }
                # Continue — comment lines never count as violations.
                next
            }
            if (stripped == "") {
                # Blank lines preserve any armed marker (so a
                # marker comment may be separated from its target by
                # a blank line if a contributor formatted it that way).
                next
            }

            # Non-comment, non-blank code line.
            if (match($0, pat)) {
                if (safe_armed == 1) {
                    # Annotated — allowed.
                    safe_armed = 0
                } else {
                    printf "  %s:%d: %s\n", file, NR, $0
                    violations++
                }
            }
            # Any non-comment line consumes the marker.
            safe_armed = 0
        }
        END { exit (violations == 0 ? 0 : 1) }
    ' "$file"
}

for pattern in "${PATTERNS[@]}"; do
    for f in "${FILES[@]}"; do
        out=$(scan_file "$f" "$pattern" 2>&1) || {
            echo "::error file=$f::KyberSlash regression — forbidden pattern '$pattern'"
            echo "$out"
            VIOLATIONS=$((VIOLATIONS + 1))
        }
    done
done

if [[ "$VIOLATIONS" -gt 0 ]]; then
    cat <<'EOF' >&2

KyberSlash regression detected.

The KyberSlash audit (doc/adr/0003-kyberslash-audit.md) requires
that every `/` and `%` on a secret-derived value use a Barrett-
style multiply-and-shift, not a literal `/` or `%` against
`KYBER_Q`. The hits above bypass that guard.

To resolve:

  1. If the operation is on a public-domain value (loop index,
     buffer length, etc.), pull `KYBER_Q` out into a local
     constant or rewrite to use a power-of-2 shift.
  2. If the operation is on a secret-derived value, replace with
     the Barrett-style approximation. Magic numbers documented
     in `crates/kyberlib/src/reference/poly.rs::poly_compress`.
  3. If the operation is provably constant-folded at compile time
     and has no secret input, add a `// kyberslash-guard: safe`
     comment on the line immediately above, citing ADR 0003.

EOF
    exit 1
fi

echo "kyberslash-guard: clean — no literal /, % against KYBER_Q in source."
