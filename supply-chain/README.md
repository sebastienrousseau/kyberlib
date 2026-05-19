# Supply-chain audits

This directory holds `cargo-vet` config and audit records for kyberlib.

## Files

| File | Purpose |
|------|---------|
| `config.toml`   | Trusted-audit imports + per-crate policy + bootstrap exemptions |
| `audits.toml`   | Audits we have performed ourselves (empty at the v0.0.7 cut) |
| `imports.lock`  | Auto-managed by `cargo vet`; pins import-set versions |

## Workflow

```sh
cargo install cargo-vet

# Fetch the latest audits from the imports
cargo vet update

# Check that every transitive dep is covered (by an import or exemption)
cargo vet check

# See what's not yet audited
cargo vet suggest

# Record an audit we performed ourselves
cargo vet certify <crate> <version> safe-to-deploy
```

## Trust model

We import audit decisions from seven well-known organisations:

| Org | Repository | Why |
|-----|-----------|-----|
| Mozilla | `mozilla/supply-chain` | Firefox-grade web crypto rigor |
| Google | `google/supply-chain` | ChromeOS / Fuchsia review |
| Bytecode Alliance | `bytecodealliance/wasmtime` | Wasmtime's vetted Rust deps |
| Embark Studios | `EmbarkStudios/rust-ecosystem` | Games-industry audited subset |
| Fermyon | `fermyon/spin` | Wasm runtime audits |
| ISRG | `divviup/libprio-rs` | Internet Security Research Group / Privacy Pass |
| Zcash | `zcash/rust-ecosystem` | Crypto-heavy curated set |

We trust each for `safe-to-deploy` and `safe-to-run`. Custom criteria
(e.g. `safe-to-deploy-fips`) may be added later — phase 5 (#170) will
revisit when the `fips` feature lands.

## Exemptions

`config.toml` carries bootstrap exemptions for the immediate dep set.
Each exemption is `suggest = false` so the entry doesn't reappear in
`cargo vet suggest` until we explicitly clear it. Quarterly review.

Tracked work: [#165](https://github.com/sebastienrousseau/kyberlib/issues/165).
