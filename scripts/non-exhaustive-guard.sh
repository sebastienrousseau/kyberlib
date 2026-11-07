#!/usr/bin/env bash
# #[non_exhaustive] guard (issue #157).
#
# Every public struct and enum in the shipped crates carries
# `#[non_exhaustive]`, so fields and variants can be added later without a
# breaking change. This script fails CI when a new one does not.
#
# A type may opt out with a comment line containing
# `non-exhaustive-guard: exempt` among the attributes and doc comments
# directly above it, followed by the reason. Path exclusions below are for
# code that is not public API.
#
# Run with:
#   bash scripts/non-exhaustive-guard.sh
#
# Wired into Makefile as `make non-exhaustive-guard`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Not public API:
#   crates/atty-compat         workspace shim mirroring the `atty` crate's API
#   crates/kyberlib/src/avx2   `mod avx2;` is private
#   .../reference/aes256ctr.rs `pub(crate) mod aes256ctr;`
mapfile -t files < <(
  find crates/kyberlib/src crates/kyberlib-asm/src crates/kyberlib-hybrid/src \
       crates/kyberlib-pkcs8/src crates/kyberlib-wasm/src -name '*.rs' \
    | grep -v -e '^crates/kyberlib/src/avx2/' \
              -e '^crates/kyberlib/src/reference/aes256ctr.rs$' \
    | sort
)

status=0
for f in "${files[@]}"; do
  awk -v file="$f" '
    # Look at the attribute/doc lines directly above each item.
    /^[[:space:]]*#\[non_exhaustive\][[:space:]]*$/ { ne = 1; next }
    /^[[:space:]]*\/\/.*non-exhaustive-guard: exempt/ { ex = 1; next }
    /^[[:space:]]*(#\[|\/\/)/ { next }
    /^[[:space:]]*pub (struct|enum) / {
      if (!ne && !ex) {
        printf "%s:%d: missing #[non_exhaustive]: %s\n", file, NR, $0
        bad = 1
      }
    }
    { ne = 0; ex = 0 }
    END { exit bad }
  ' "$f" || status=1
done

if [ "$status" -ne 0 ]; then
  echo "Add #[non_exhaustive], or an annotated exemption with a reason (#157)." >&2
  exit 1
fi
echo "non-exhaustive guard: ${#files[@]} files clean"
