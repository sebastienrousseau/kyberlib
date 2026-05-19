# Contributing to kyberlib

Thanks for considering a contribution. kyberlib is a cryptographic library —
that means contributions face a higher bar than your average crate, and the
review cycle takes correspondingly longer. This document explains the bar
and the process.

If you only have a few minutes, the bullet version is at the bottom.

## Code of conduct

By participating, you agree to the [Code of Conduct][coc].

[coc]: https://github.com/sebastienrousseau/kyberlib/blob/main/.github/CODE-OF-CONDUCT.md

## Prerequisites

- **Rust toolchain:** stable, pinned via `rust-toolchain.toml`. Run
  `rustup show` once in the repo to install the right components.
- **MSRV:** Rust **1.74.0**. Every PR is checked against this in CI; if you
  use a feature introduced after 1.74, the build fails.
- **Optional but useful:**
  - `cargo-deny` (`cargo install cargo-deny`)
  - `cargo-vet`  (`cargo install cargo-vet`)
  - `cargo-machete` (`cargo install cargo-machete`)
  - `cargo-fuzz` (nightly only) for `fuzz/`
  - `miri` (`rustup +nightly component add miri`)

## Repository layout (post-v0.0.7)

The v0.0.7 enterprise-upgrade splits kyberlib into a workspace
(see [#128][i128] for status):

```
crates/
  kyberlib/         # safe core, no_std + alloc, #![forbid(unsafe_code)]
  kyberlib-asm/     # AVX2 / NEON acceleration (unsafe quarantined here)
  kyberlib-wasm/    # wasm-bindgen JS shim
  kyberlib-fuzz/    # cargo-fuzz targets (publish=false)
  xtask/            # internal release tooling (publish=false)
```

Until that phase lands, the repo is a single crate at the root.

## Branch naming

We use Conventional-Commits-style prefixes:

| Prefix       | When to use it                                          |
|--------------|---------------------------------------------------------|
| `feat/…`     | New public-facing capability                            |
| `fix/…`      | Bug fix to existing behaviour                           |
| `perf/…`     | Performance optimisation; no behaviour change           |
| `refactor/…` | Code reshape; no behaviour change, no perf claim        |
| `docs/…`     | Documentation only                                      |
| `test/…`     | Test changes only                                       |
| `ci/…`       | CI / build pipeline only                                |
| `chore/…`    | Dependency bumps, housekeeping                          |
| `security/…` | Security-relevant fix (use the email channel first;     |
|              | see SECURITY.md)                                        |

Example: `fix/keypair-import-secret-zeroize`.

## Commit messages

Conventional Commits 1.0 — `<type>(<scope>): <subject>`.

Types: `feat | fix | perf | refactor | docs | test | ci | chore | build |
revert`.

Examples:

```
fix(api): drop Copy from Keypair to honor ZeroizeOnDrop
docs(security): document FIPS 203 conformance path
ci: pin reusable workflow to commit SHA, not @main
```

Subject is imperative ("add" not "added"), ≤ 70 chars. Body wrapped at 72.
Reference the issue number (`Closes #138`) on the last line of the body
when applicable.

## Signed commits required

`main` rejects unsigned commits. Configure GPG or SSH commit signing
([GitHub guide][sign]). The `verify-signatures` CI gate ([#141][i141]) will
fail PRs with unsigned commits.

[sign]: https://docs.github.com/en/authentication/managing-commit-signature-verification

## Pull request checklist

Before opening a PR, your branch must pass:

```sh
cargo +1.74.0 build --all-features
cargo test --all-features
cargo test --no-default-features --features kyber768
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
cargo doc --no-deps --all-features              # rustdoc must be clean
cargo deny check                                 # licenses, advisories, sources
```

For changes that touch crypto paths (`src/reference/`, `src/avx2/`,
`src/symmetric.rs`, `src/kem.rs`), additionally:

```sh
RUSTFLAGS="-C target-feature=+aes,+avx2" cargo test --features avx2,std
cargo +nightly miri test --lib                  # focused subset
cargo fuzz run fuzz_decap -- -runs=1000000      # 1M iterations smoke
```

Open the PR with:

- **Title** matching the Conventional Commits commit subject.
- **Description** that answers: *what changed*, *why*, *risk*, *test plan*.
  For breaking changes, include a "Migration" section.
- **Linked issues** (`Closes #N`, `Refs #N`).
- **CI green** — re-run failures only if you've addressed them; don't
  flake-retry.

## Tests

- **Unit/integration tests** live in `tests/`. New behaviour ships with a
  test in the same PR.
- **KAT / ACVP vectors:** during the v0.0.7 spec migration we'll move the
  authoritative vectors from pq-crystals Kyber R3 (`tests/KAT/`) to NIST
  ACVP ML-KEM JSON (`tests/acvp/`). See [#148][i148].
- **Doctests:** every `pub` function / type has a doctest exercising the
  golden path. `cargo test --doc` must stay green.

## Documentation

- Every `pub` item carries rustdoc (`#![deny(missing_docs)]` at the crate
  root). The format is: summary line · `# Examples` · `# Errors` ·
  `# Panics` (if any).
- For security-relevant changes, update `SECURITY.md`.
- For breaking changes, add a `CHANGELOG.md` entry under `[Unreleased] →
  Changed` (and `→ Migration` if user action is required).

## ADR process

For decisions that change the **public API**, **algorithm conformance**, or
**security posture**, write an Architecture Decision Record under
`doc/adr/`:

```
doc/adr/
  0001-fips203-migration.md
  0002-trait-based-api.md
  TEMPLATE.md
```

The ADR ships in the same PR as the change. Use `doc/adr/TEMPLATE.md`.

## Crypto-specific conventions

These overrule the general Rust style guide where they conflict.

1. **No `/` or `%` on secret-derived integers.** Use Barrett or Montgomery
   reduction. KyberSlash (TCHES 2025) and CVE-2026-22705 (Feb 2026) both
   exploited this exact class of bug.
2. **No data-dependent branches on secret material.** Use the constant-time
   `verify` and `cmov` helpers in `src/reference/verify.rs`.
3. **No allocations in the hot path.** kyberlib must build `no_std + alloc`.
4. **Public types holding secrets:** `!Copy`, `ZeroizeOnDrop`, redacted
   `Debug` impl.
5. **`unsafe` lives in `crates/kyberlib-asm/` only.** The core crate
   `#![forbid(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:`
   comment.

## Bug reports

[Open an issue][issues]. Include:

- kyberlib version (`cargo pkgid kyberlib` output),
- Rust toolchain version (`rustc -V`),
- target triple (`rustc -Vv | grep host`),
- enabled features,
- minimal reproducer (a 30-line `main.rs` ideally),
- expected vs observed behaviour.

For **security** bugs, use the email channel in `SECURITY.md` — **do not**
open a public issue.

[issues]: https://github.com/sebastienrousseau/kyberlib/issues

## Feature requests

Open an issue first, *before* writing code. Cryptographic libraries earn
trust by saying "no" to features more often than "yes" — please don't be
surprised if we push back on additions to the API surface.

## License

kyberlib is dual-licensed under [MIT][mit] **or** [Apache-2.0][apl] at the
user's option. By submitting a contribution, you agree that your work is
licensed under both.

[mit]: https://github.com/sebastienrousseau/kyberlib/blob/main/LICENSE-MIT
[apl]: https://github.com/sebastienrousseau/kyberlib/blob/main/LICENSE-APACHE

## The bullet version

- Branch: `feat/…` / `fix/…` / etc.
- Conventional Commits, signed.
- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --all-features`,
  `cargo doc --no-deps -- -D warnings` all green.
- Test for every new behaviour.
- For crypto changes: add a doctest, run `dudect`, run fuzz for 1M iters.
- For breaking changes: CHANGELOG entry + ADR.

[i128]: https://github.com/sebastienrousseau/kyberlib/issues/128
[i141]: https://github.com/sebastienrousseau/kyberlib/issues/141
[i148]: https://github.com/sebastienrousseau/kyberlib/issues/148
