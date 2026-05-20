# `kyberlib-pkcs8` — additional documentation

The authoritative API reference lives on [docs.rs/kyberlib-pkcs8](https://docs.rs/kyberlib-pkcs8).
This directory holds longer-form material that doesn't fit in
`///` rustdoc on the items themselves — design notes, ADRs that
cite this crate specifically, migration guides, and reference
test-vector summaries.

When adding a document here, also link it from:
* the crate-level `//!` block in `src/lib.rs` (or the top-level
  README.md if the doc is consumer-facing)
* the workspace [`doc/` directory](../../../doc/) for cross-crate
  ADRs.
