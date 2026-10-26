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

## Format notes

`cargo vet` owns the layout of `config.toml`, `audits.toml` and
`imports.lock` and rejects a hand-formatted file (`cargo vet fmt`
rewrites it). Comments in those files do not survive, so the reasoning
lives here:

- The exemptions are grouped by role: production dependencies
  (`safe-to-deploy`), build dependencies (`cc`, `nasm-rs`; `safe-to-run`,
  they only execute at build time) and dev dependencies (`criterion`,
  `serde`, `serde_json`, `wasm-bindgen-test`; `safe-to-run`, they only
  enter test and bench binaries).
- `serde` and `serde_json` were exempted as `"1.0"`, which cargo-vet
  never accepted: it needs an exact version, so the whole file failed to
  parse and `cargo vet` never ran. They are pinned to the versions the
  lockfile carried when the format was fixed (1.0.229 and 1.0.151),
  narrower than the original intent, never looser.
- `kyberlib-asm` is `publish = false`, so its policy no longer asks
  cargo-vet to audit it as a crates.io crate (that lookup failed).
- `exemptions-baseline.txt` is the ceiling CI holds the exemption count
  to: it may go down, never up.
