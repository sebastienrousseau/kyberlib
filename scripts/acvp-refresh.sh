#!/usr/bin/env bash
# Refresh NIST ACVP ML-KEM test vectors.
#
# Re-downloads `prompt.json` and `expectedResults.json` for both
# `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203` from the
# canonical NIST ACVP-Server repository, then verifies SHA-256s
# against the checked-in `SHA256SUMS`.
#
# Run from anywhere in the repo:
#
#   bash scripts/acvp-refresh.sh
#
# Pass `--update-sums` to overwrite SHA256SUMS with the new digests
# (use this when intentionally pulling fresh upstream vectors):
#
#   bash scripts/acvp-refresh.sh --update-sums

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VECTORS_DIR="$REPO_ROOT/crates/kyberlib/tests/acvp"
BASE_URL="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"

UPDATE_SUMS="false"
if [[ "${1:-}" == "--update-sums" ]]; then
    UPDATE_SUMS="true"
fi

declare -a FILES=(
    "ML-KEM-keyGen-FIPS203/prompt.json:keyGen-prompt.json"
    "ML-KEM-keyGen-FIPS203/expectedResults.json:keyGen-expected.json"
    "ML-KEM-encapDecap-FIPS203/prompt.json:encapDecap-prompt.json"
    "ML-KEM-encapDecap-FIPS203/expectedResults.json:encapDecap-expected.json"
)

mkdir -p "$VECTORS_DIR"
cd "$VECTORS_DIR"

echo "Downloading ACVP ML-KEM vectors → $VECTORS_DIR"
for entry in "${FILES[@]}"; do
    remote="${entry%%:*}"
    local="${entry##*:}"
    url="$BASE_URL/$remote"
    echo "  $local"
    curl -fsSL "$url" -o "$local"
done

if [[ "$UPDATE_SUMS" == "true" ]]; then
    echo "Updating SHA256SUMS"
    shasum -a 256 keyGen-prompt.json keyGen-expected.json \
                  encapDecap-prompt.json encapDecap-expected.json \
        > SHA256SUMS
    echo "SHA256SUMS updated. Commit the new digests if vectors changed."
else
    echo "Verifying SHA-256s against checked-in SHA256SUMS"
    if shasum -a 256 -c SHA256SUMS; then
        echo "OK — vectors match checked-in hashes."
    else
        echo "FAIL — vectors do not match SHA256SUMS." >&2
        echo "  If NIST has published an update, re-run with --update-sums" >&2
        echo "  and review the diff carefully before committing." >&2
        exit 1
    fi
fi
