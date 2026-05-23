# kyberlib — v0.0.7 enterprise upgrade plan

Living document tracking the work that turned kyberlib from a
hobbyist-grade CRYSTALS-Kyber wrapper (v0.0.6) into a FIPS 203
ML-KEM crate suitable for enterprise + CNSA 2.0 deployments. Each
phase corresponds to a milestone tracked in the `v0.0.7` GitHub
issue set (`gh issue list --milestone v0.0.7`).

## Status legend

* ✅ Landed
* 🚧 In progress
* 📋 Tracked, not started
* ⏸  Deferred — see linked ADR

---

## Phase 0 — Foundation

* ✅ **#128** Workspace split: `kyberlib` (safe core) + satellite
  crates `kyberlib-asm`, `kyberlib-hybrid`, `kyberlib-pkcs8`,
  `kyberlib-wasm`.
* ✅ **#137** `#![deny(missing_docs)]` on the safe core; every
  public item carries `///` documentation.
* ✅ **#141** Reusable CI workflow pinned by commit SHA;
  `permissions: contents: read` baseline.

## Phase 1 — Safety architecture

* ✅ **#143** AVX2 quarantine. Granular unsafe-code gate in the safe
  core: `forbid(unsafe_code)` under default features;
  `deny(unsafe_code)` + per-module `allow(unsafe_code)` only on
  `mod avx2;` when `--features avx2`. Documented in
  [ADR 0002][adr0002].
* ✅ **#144** `kyberlib-wasm` split out — the safe core has no
  `wasm-bindgen` dependency.

## Phase 2 — FIPS 203 spec migration

* ✅ **#149** KyberSlash audit (ADR 0003). Every secret-dependent
  `/` or `%` against `KYBER_Q = 3329` replaced by Barrett-style
  multiply-and-shift, inherited from pq-crystals upstream.
  Regression gate: `scripts/kyberslash-guard.sh`.
* ✅ Spec migration commits `417595a` / `27e4b6b` / `b0f3bfb` —
  domain-separator byte in `G(d ‖ K)`, removal of pre-FO `m' = H(m)`,
  removal of post-KDF wrap.

## Phase 3 — Typed-state API + multi-parameter-set

The "multi-day refactor" — turn the cfg-gated single-parameter
backend into a generic-over-`MlKemParams` library where all three
parameter sets coexist in one build.

* ✅ **Phase 3a** Foundation (`a77b94b`). `MlKemParams` trait + impls
  for the three markers. 10 unit tests.
* ✅ **Phase 3b** First algorithm port (`839a831`).
  `polyvec_compress_generic<P>`, byte-validated against existing.
* ✅ **Phase 3b** 11 more primitive ports (`9261088`).
  polyvec / poly / cbd surface fully generic; 29 byte-equality tests.
* ✅ **Phase 3c** Composition layer (`3ac681a`, `051cff9`).
  `gen_matrix`, `indcpa_keypair`, `indcpa_enc`, `indcpa_dec`,
  `kem_keypair`, `kem_enc`, `kem_dec` all generic over `P`.
* ✅ **Phase 3d** Generic noise sampling (`3819f7a`). Closes the
  last cfg-gated call site in the generic pipeline.
* ✅ **Phase 3e** Public `KemCore` API rewire (`eabbc6d`). All three
  `MlKem*::generate` paths route through the generic pipeline.
* ✅ **Phase 3g** ACVP harness across all three sets (`67357c0`).
  **180 / 180 NIST vectors green.**
* ⏸  **Phase 3f** Drop the `kyber*` mutual-exclusion `compile_error!`.
  Optional follow-up — the legacy `crate::api` free-function surface
  still selects one parameter set per build; the typed `MlKem*`
  surface is multi-param without the change.

## Phase 4 — Security tooling

* ✅ **#161 gating condition** dudect harness wired
  (`crates/kyberlib/benches/dudect.rs`). Two CT-leak benches
  (`decap_valid_vs_invalid_ct`, `decap_real_pairs`) pass at ±10σ
  under 10k samples.
* ✅ **#149-followup** KyberSlash regression gate in CI
  (`bash scripts/kyberslash-guard.sh`).
* ✅ Miri focused suite (`scripts/miri.sh focused`) in CI;
  full + big-endian sweep available via `scripts/miri.sh full`.
* ✅ Fuzz smoke (`fuzz/fuzz_targets/*`) — four libfuzzer targets,
  10-second compile-only run on every PR.

## Phase 5 — Audit deliverables

Each audit landed as a multi-commit bundle, all 7 audit areas:

1. ✅ **Cargo / workspace hygiene** (`267b114`) — `rand` runtime-dep
   removal, FIPS-203 description, `dep:` syntax, drop no-op
   features, workspace lints.
2. ✅ **Public API** (`267b114` + follow-ups) — `Hash` on
   `KyberLibError`, intra-doc links, closed doctest fences,
   `MlKem768::ALGORITHM_ID` naming consistency. Larger refactors
   (`thiserror`, `subtle::ConstantTimeEq`, `Uake::eska` privatisation)
   documented as separate-PR work.
3. ✅ **DevSecOps / CI** (`267b114` + `5b651b5` …) — explicit
   in-repo lint job, `--locked` everywhere, bumped actions/checkout
   to v4.2.2, codified pedantic clippy cohort thresholds.
4. ✅ **SDET / testing** (`267b114`) — 6 proptest properties,
   insta snapshot redaction gate, cargo-llvm-cov coverage gate,
   dedicated `coverage` CI job.
5. ✅ **Performance / release** (`735d2a6`) — tarball trimmed
   1.9 MiB → 475 KiB (−75%) by tightening the `include` glob;
   `criterion::black_box` everywhere; wire all 8 bench targets.
6. ✅ **Rustdoc** (`56ce50d`) — refresh crate + module docs to
   FIPS 203 ML-KEM branding, intra-doc links everywhere, `//!`
   blocks on the 5 previously-undocumented modules.
7. ✅ **Performance / release** (`735d2a6`) — already counted under
   audit #5.

## Phase 6 — Release infrastructure

* ✅ **Tag-driven release** via `.github/workflows/release.yml`.
  SLSA L3 build provenance (Rekor transparency log), cosign keyless
  blob signing (Fulcio + Rekor), CycloneDX 1.6 CBOM via
  `scripts/cbom.sh`.
* ✅ Verification recipe documented in `release.yml` header.
* 📋 **#173 follow-up** — attach the CBOM to every GitHub Release
  alongside the `.crate` file + cosign bundle.

## Phase 7 — Layout consistency (THIS commit)

Bring the repo layout into line with the noyalib reference for
consistency across the contributor's Rust projects.

* ✅ Phase 7.1 universal hygiene — `.editorconfig`,
  `.gitattributes`, root-level `LICENSE-APACHE` / `LICENSE-MIT`,
  `LICENSES/` dir, rename `rustfmt.toml` → `.rustfmt.toml`.
* ✅ Phase 7.2 project documentation (this file +
  `GETTING_STARTED.md` + `GLOSSARY.md`).
* ✅ Phase 7.3 per-crate consistency — `LICENSE-APACHE` /
  `LICENSE-MIT` / `doc/` / `examples/` / `tests/` / `benches/` on
  every workspace member.
* ✅ Phase 7.4 `xtask/` workspace member — Rust-native task runner
  wrapping `scripts/*.sh` invocations.

## Out of scope for v0.0.7

The following items are tracked but deferred to v0.1 or beyond:

* **#170** `fips` Cargo feature delegating to `aws-lc-rs`. The
  CMVP validation path. Requires upstream FIPS-validated ML-KEM
  binding; aws-lc-fips 3.0 ships ML-KEM but the binding is
  in-progress.
* **#171** `verified` Cargo feature delegating to `libcrux-ml-kem`.
  F* + hax-verified backend. Symbolic Software's eprint 2026/192
  found three bugs in libcrux's verified surface; we're tracking
  remediation before adopting.
* **#177** `kyberlib-hybrid` activation. The crate scaffolding is
  in place; the FIPS 203-conformant X25519MLKEM768 implementation
  per draft-ietf-tls-ecdhe-mlkem-04 lands in v0.1.
* **#143 file-level relocation** of the AVX2 backend into
  `kyberlib-asm`. The safety property has already landed via the
  granular unsafe gate (Phase 1, ADR 0002); the file move is pure
  housekeeping.

## How to update this file

When a phase lands, flip its ✅ marker and add the commit hash. When
a new phase is planned, append below the last completed phase with a
📋 marker. Keep the audit-deliverable section (Phase 5) sorted by
its issue number; the work-in-progress section (Phases 3–4) sorted
chronologically.

[adr0002]: ./doc/adr/0002-asm-quarantine.md
