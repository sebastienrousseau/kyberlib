# Policies: versioning, minimum Rust version, stability

> Last Updated: 2026-11-07

## Versioning

kyberlib is pre-1.0. Releases go up by `0.0.1` at a time (`0.0.14`,
`0.0.15`, ...), and `0.1.0` follows `0.0.999`. While the version is
`0.0.x`, **the patch number is the breaking axis**: any release may
break source compatibility, and its CHANGELOG section says how. Every
crate in the workspace shares one version.

`v1.0.0` is the first release that freezes the API. Its bar is
[`RELEASE-1.0-CHECKLIST.md`](RELEASE-1.0-CHECKLIST.md), including a
third-party audit.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) is **1.89**, declared as
`rust-version` in the workspace manifest. The `MSRV (Rust 1.89)` CI job
checks `kyberlib` and `kyberlib-pkcs8` (every feature) with that
toolchain on every pull request.

The MSRV may rise in any release. The release that raises it says so,
with the reason, in its CHANGELOG section; 0.0.11 raised it from 1.74 to
1.89, the floor shared by the maintainer's Rust crates. kyberlib makes
no promise about the Rust versions shipped by Linux distributions.

## What counts as a breaking change

- **The public API**: removing or renaming an item, changing a
  signature, or adding a required trait bound. `cargo-semver-checks`
  runs in CI against the last published release. Public structs and
  enums are `#[non_exhaustive]` so fields and variants can be added
  without breaking callers (#157).
- **Bytes on the wire and on disk.** Keys, ciphertexts and shared
  secrets follow FIPS 203 exactly; key files follow RFC 9935. A change
  to any of these bytes is breaking even if no signature moves.
- **The hybrid wire format.** `kyberlib-hybrid` implements
  `draft-ietf-tls-ecdhe-mlkem-05` and `draft-connolly-cfrg-xwing-kem-11`.
  Moving to a new draft revision that changes bytes on the wire is a
  breaking change, made in a normal `0.0.x` release that names the new
  revision in its CHANGELOG.
- **Cargo features**: removing a feature or changing what it enables.

## Deprecation

Before `v0.1`, deprecation is documented rather than enforced: a
soft-deprecated item (today, the legacy `Keypair` and the free
functions) stays working and its documentation points to the
replacement. `#[deprecated]` attributes start at `v0.1`.
