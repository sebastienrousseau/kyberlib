# Audit readiness checklist

> Maintainer self-assessment before sending out the RFP. Each item is
> either ✅ (ready), 🟡 (partial / known gap), or ❌ (not yet). The
> goal is that the auditor doesn't *discover* any 🟡 / ❌ on our dime.

## Conformance

| Item | Status | Notes |
|------|:------:|-------|
| FIPS 203 byte-level conformance | ✅ | 60 / 60 ACVP ML-KEM-768 cases pass (commit `b0f3bfb`) |
| ACVP harness committed and reproducible | ✅ | `crates/kyberlib/tests/test_acvp.rs` + checked-in vectors + SHA256SUMS |
| All three Round-3 → FIPS-203 patches documented | ✅ | `doc/patches/phase-2b-evidence.md` + commit messages on `417595a` / `27e4b6b` / `b0f3bfb` |
| ML-KEM-512 / ML-KEM-1024 | 🟡 | Marker types declared, implementation pending #130b. Out of scope per RFP §3.2. |
| OID re-exports from core | 🟡 | Currently in `kyberlib-pkcs8`; #150 will re-export from core too |

## Side-channel hardening

| Item | Status | Notes |
|------|:------:|-------|
| KyberSlash audit completed | ✅ | ADR 0003; 5 safe sites annotated; static regression guard in CI |
| Constant-time `verify` / `cmov` | ✅ | Audited bitwise (`crates/kyberlib/src/reference/verify.rs`) |
| `decapsulate` implicit-rejection invariant | ✅ | FIPS 203 §6.3 — never panics, never branches on validity. Documented and fuzz-tested. |
| Secret-key `!Copy` + `ZeroizeOnDrop` | ✅ | `MlKem768DecapKey` and legacy `Keypair` |
| `dudect` statistical CT test | ❌ | Scaffolded (`scripts/dudect.sh`) but the `dudect-bencher` integration is future work. RFP §9 accepts. |
| Side-channel docs in `SECURITY.md` | ✅ | Per-function CT guarantee table |

## API design

| Item | Status | Notes |
|------|:------:|-------|
| Typed `EncapsulationKey` / `DecapsulationKey` split | ✅ | `crates/kyberlib/src/ml_kem.rs` |
| Sealed `KemCore` trait | ✅ | Same file |
| `#[non_exhaustive]` on `KyberLibError` | ✅ | `crates/kyberlib/src/error.rs` |
| Redacted `Debug` impls on secrets | ✅ | `SharedSecret`, `MlKem768DecapKey`, `X25519MlKem768Client`, `X25519MlKem768SharedSecret` |
| Length-validated constructors | ✅ | `try_from_slice` on the typed wrappers |
| Old API soft-deprecated, still works | ✅ | `Keypair`, `keypair()`, `encapsulate()`, `decapsulate()` retained |
| Hybrid KEM (X25519MlKem768) wired | ✅ | `crates/kyberlib-hybrid/src/lib.rs` |
| Hybrid wire format matches draft-04 | ✅ | round-trip test confirms; `Hybrid` trait surfaces the lengths to the type system |

## `unsafe` surface

| Item | Status | Notes |
|------|:------:|-------|
| Safe core `#![forbid(unsafe_code)]` (no-feature build path) | ✅ | `crates/kyberlib/src/lib.rs` cfg-gated forbid |
| AVX2 backend isolated by feature | 🟡 | Currently `crates/kyberlib/src/avx2/`; the move to `crates/kyberlib-asm` is tracked under #143 (ADR 0002). AVX2 code is reachable today via `cargo build --features avx2`. |
| `// SAFETY:` justification on every unsafe block | 🟡 | Many blocks are wrappers around SIMD intrinsics; not all carry inline SAFETY comments. RFP §3.1 explicitly asks the auditor to flag missing ones. |

## Supply chain

| Item | Status | Notes |
|------|:------:|-------|
| `cargo deny` policy + CI gate | ✅ | `deny.toml`; advisories OK, bans OK, licenses OK, sources OK |
| `cargo vet` imports from trusted orgs | ✅ | `supply-chain/config.toml` imports from Mozilla, Google, Bytecode Alliance, ISRG, Embark, Fermyon, Zcash |
| `cargo vet` exemptions documented | 🟡 | Bootstrap exemptions in `supply-chain/config.toml`; quarterly review cadence not yet exercised |
| GitHub Actions SHA-pinned (no `@vN`, no `@main`) | ✅ | All `uses:` in `ci.yml` and `release.yml` |
| `Cargo.lock` committed | ✅ | Reproducible builds |
| No git-source deps | ✅ | Dropped `commons` in Phase 0 |
| RUSTSEC advisories checked | ✅ | `RUSTSEC-2026-0097` (rand 0.8 unsoundness) closed by bump |

## Release / provenance

| Item | Status | Notes |
|------|:------:|-------|
| Tag-triggered release workflow | ✅ | `.github/workflows/release.yml` |
| SLSA L3 build provenance | ✅ | `actions/attest-build-provenance` in `release.yml` |
| Keyless cosign signing | ✅ | Fulcio + Rekor via OIDC |
| CycloneDX 1.6 CBOM | ✅ | `scripts/cbom.sh`; wired into release pipeline |
| Verification recipe documented | ✅ | `SECURITY.md` §"Supply Chain" + `release.yml` comment |
| First dry-run executed | ❌ | Workflow exists but not yet exercised. Plan to dry-run before signing audit contract. |

## Tests + CI

| Item | Status | Notes |
|------|:------:|-------|
| Workspace test count | ✅ | 148 tests + 25 doctests, all green |
| Cross-platform CI (Linux, macOS, Windows) | ✅ | `ci.yml` matrix |
| MSRV gate (1.74) | ✅ | dedicated job |
| no_std gate | ✅ | `cargo check -p kyberlib --lib --no-default-features --features kyber768` |
| Vendor / air-gap build simulation | ✅ | `vendor-build` job |
| Strict rustdoc | ✅ | `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links ..."` |
| `cargo fmt --all --check` enforced | ✅ | CI gate |
| `cargo clippy --workspace --all-features -- -D warnings` clean | ✅ | CI gate |
| Per-PR Miri (focused) | ✅ | `miri-focused` job in `ci.yml` |
| Fuzz smoke (10 s) per PR | ✅ | `fuzz-smoke` job (soft-fail today) |
| `kyberslash-guard` per PR | ✅ | New in this commit series |

## Documentation

| Item | Status | Notes |
|------|:------:|-------|
| README has install + quickstart + badges | ✅ | |
| CHANGELOG (Keep-a-Changelog) | ✅ | v0.0.7 entry comprehensive |
| SECURITY.md with threat model + CT claims + disclosure SLA | ✅ | |
| CONTRIBUTING.md with conventional commits + signed-commits requirement | ✅ | |
| ADR series (0001 / 0002 / 0003) | ✅ | All three ADRs landed |
| Per-public-item rustdoc enforced | ✅ | `#![deny(missing_docs)]` on the safe core |
| Comparison vs. competitors | ✅ | `doc/COMPARISON.md` |
| Audit packet | ✅ | `doc/audits/` (this directory) |

## Aggregate

* ✅ 38 items
* 🟡 5 items (all called out in RFP §3.2 or §9 — auditor expects them)
* ❌ 2 items (`dudect` and the release-pipeline dry-run — neither is
  on the critical path for audit kickoff)

**Verdict:** kyberlib is ready for audit. The maintainer's remaining
pre-RFP-send tasks are:

1. Run a `release.yml` workflow_dispatch with `dry_run = true` and
   verify the artefacts (SBOM, CBOM, attestation, cosign sig). *(In
   progress this commit series.)*
2. ~~Fill in the four `<TBD>` placeholders in `RFP-v1.0.md`.~~ *(Done
   — see the four `[ADJUST]` flags; confirm before sending.)*
3. Pick 2–3 vendors from RFP §7 and send.
