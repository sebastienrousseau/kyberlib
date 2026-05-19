#!/usr/bin/env bash
# Generate a CycloneDX 1.6 CBOM (Cryptographic Bill of Materials) for
# kyberlib. EU CRA + NIS2 + an increasing slice of US federal procurement
# now ask for a CBOM alongside the SBOM for any package that ships
# cryptographic primitives.
#
# CycloneDX 1.6 added the `cryptoProperties` block specifically for
# this purpose: per-component declaration of algorithms, parameter
# sets, certification status, etc.
#
# Workflow:
#   1. `cargo cyclonedx` produces an SBOM in CycloneDX 1.5 / 1.6 JSON.
#   2. This script post-processes the JSON to inject `cryptoProperties`
#      blocks for kyberlib and its workspace members.
#   3. Output is written to `target/cbom.cdx.json`.
#
# Run with:
#   bash scripts/cbom.sh
#
# Requires:
#   - cargo install cargo-cyclonedx
#   - jq

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="target"
SBOM_PATH="$OUT_DIR/bom.json"
CBOM_PATH="$OUT_DIR/cbom.cdx.json"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (brew install jq / apt install jq)" >&2
    exit 1
fi

if ! cargo cyclonedx --version >/dev/null 2>&1; then
    echo "ERROR: cargo-cyclonedx not installed."             >&2
    echo "Run: cargo install cargo-cyclonedx --locked"        >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

echo ":: generating CycloneDX 1.5 SBOM via cargo-cyclonedx"
# `cargo-cyclonedx` 0.5.x tops at CycloneDX 1.5. We generate 1.5
# and post-process below to bump `specVersion` to 1.6 + inject
# the `cryptoProperties` block introduced in 1.6.
cargo cyclonedx \
    --format json \
    --spec-version 1.5 \
    --override-filename bom \
    --all \
    > /dev/null

# cargo-cyclonedx writes per-crate `bom.json` files at the
# manifest path. Pick the workspace-root one for post-processing.
if [[ -f "bom.json" ]]; then
    mv bom.json "$SBOM_PATH"
elif [[ -f "crates/kyberlib/bom.json" ]]; then
    cp crates/kyberlib/bom.json "$SBOM_PATH"
fi

echo ":: bumping specVersion 1.5 → 1.6 and injecting cryptoProperties"
jq '
  .specVersion = "1.6"
  | .components |= map(
    if .name == "kyberlib" then
      . + {
        "cryptoProperties": {
          "assetType": "algorithm",
          "algorithmProperties": {
            "primitive": "kem",
            "parameterSetIdentifier": "ML-KEM-768",
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "x86_64",
            "certificationLevel": ["none"],
            "mode": "cca",
            "padding": "implicit-rejection",
            "cryptoFunctions": ["keygen", "encapsulate", "decapsulate"],
            "classicalSecurityLevel": 192,
            "nistQuantumSecurityLevel": 3
          },
          "oid": "2.16.840.1.101.3.4.4.2"
        }
      }
    elif .name == "kyberlib-asm" then
      . + {
        "cryptoProperties": {
          "assetType": "algorithm",
          "algorithmProperties": {
            "primitive": "kem",
            "parameterSetIdentifier": "ML-KEM-768",
            "executionEnvironment": "software-plain-ram",
            "implementationPlatform": "x86_64-avx2",
            "certificationLevel": ["none"]
          }
        }
      }
    elif .name == "kyberlib-wasm" then
      . + {
        "cryptoProperties": {
          "assetType": "algorithm",
          "algorithmProperties": {
            "primitive": "kem",
            "parameterSetIdentifier": "ML-KEM-768",
            "executionEnvironment": "browser-wasm",
            "implementationPlatform": "wasm32"
          }
        }
      }
    else . end
  )
  | .metadata.properties = (.metadata.properties // []) + [
      { "name": "kyberlib:phase", "value": "v0.0.7 enterprise upgrade" },
      { "name": "kyberlib:fips203-conformance", "value": "pending — see issue #147" }
    ]
' "$SBOM_PATH" > "$CBOM_PATH"

echo ":: CBOM written to $CBOM_PATH"
echo "   ($(wc -c < "$CBOM_PATH") bytes)"
echo
echo "Validate with:"
echo "  python3 -c \"import json; json.load(open('$CBOM_PATH'))\" && echo OK"
echo
echo "Phase 6 (#173) attaches this output to the GitHub Release alongside the"
echo ".crate file and its cosign signature."
