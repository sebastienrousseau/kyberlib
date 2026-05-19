# kyberlib — Third-Party Security Audit RFP (v1.0)

> **Sending instructions for the maintainer:** fill in the four `<TBD>`
> placeholders below (budget cap, target start date, point-of-contact
> name + email, payment terms), then send this document together with
> `MATERIALS.md` to two or three vendors from §7. Expect 1–2 weeks of
> back-and-forth on scope and quote before signing.

---

## 1. Project at a glance

* **Name:** kyberlib
* **Language:** Rust (edition 2021, MSRV 1.74)
* **License:** MIT OR Apache-2.0 (dual)
* **Repository:** <https://github.com/sebastienrousseau/kyberlib>
* **Audit target branch / tag:** `feat/v0.0.7` → will be tagged
  `v0.0.7` once this audit closes; the same code is intended to
  carry `v1.0.0` after remediation.
* **Maintainer / point-of-contact:** `<TBD>`
* **Disclosure channel:** see `SECURITY.md` (email only, 48 h ack,
  7 d triage SLA).
* **Code statistics (workspace):**
  - 5 publishable + non-publishable Rust crates
  - ~7 000 LoC of Rust (incl. AVX2 + reference backends)
  - ~ 4 000 LoC of GAS / NASM assembly (AVX2 backend)
  - 148 tests, 60 / 60 NIST ACVP ML-KEM-768 cases pass, 25 doctests
  - Coverage gate: ≥ 80% lines (CI-enforced)

## 2. Background

kyberlib is a Rust implementation of **FIPS 203 ML-KEM** (the
post-quantum key-encapsulation mechanism standardised by NIST in
August 2024). The v0.0.7 release closes a multi-month enterprise-
hardening cycle:

* Migrated primitives from Kyber Round 3 to FIPS 203 (`ADR 0001`,
  commits `417595a` / `27e4b6b` / `b0f3bfb`).
* Wired the NIST ACVP corpus as the gating conformance harness
  (commit `d6ded86`; 60 / 60 ML-KEM-768 cases pass).
* Audited and gated the KyberSlash class of timing side-channels
  (`ADR 0003`, commit `18ba0d9`).
* Split the workspace into a safe core (`#![forbid(unsafe_code)]`
  in the common build path) and an opt-in `kyberlib-asm` /
  `kyberlib-wasm` periphery (`ADR 0002`).
* Added a typed ML-KEM-768 API alongside the legacy flat surface
  (commit `a6065cc`).
* Implemented the X25519MlKem768 hybrid per
  `draft-ietf-tls-ecdhe-mlkem-04` (commit `5eb7bd5`).
* Added a tag-triggered release pipeline with SLSA L3 attestation +
  keyless cosign signing + CycloneDX 1.6 CBOM (Phase 6.1).

The v1.0.0 release will not ship until this audit signs off.

## 3. Audit scope

### 3.1 In scope

| Area | What we want reviewed |
|------|------------------------|
| **FIPS 203 conformance** | Spot-check our reading of §5.1 / §6.1 / §6.2 / §6.3 against the kyberlib primitives. ACVP is byte-equality; an audit catches the semantic gaps ACVP can't (e.g. an algebraic bug that happens to match expected vectors). |
| **Constant-time properties** | Per-function CT claims in `SECURITY.md`. Particular attention to `decapsulate`, `verify`, `cmov`, and the rejection-sampling loop in `gen_matrix`. KyberSlash class explicitly. |
| **Public API design** | The `KemCore` trait, `MlKem768EncapKey` / `MlKem768DecapKey` split, the deprecation strategy for the legacy `Keypair`/`keypair()` surface. Look for footguns and ergonomic traps. |
| **Hybrid KEM** | X25519MlKem768 wire-format byte order, share-length validation, secret-secret concatenation order, dependency on `x25519-dalek`'s contract. |
| **Side-channel attacks beyond timing** | Power and EM are out of scope; software-observable channels (memory access patterns, branch mispredictions, cache footprint) are in. |
| **`unsafe` surface** | `crates/kyberlib-asm/` (when populated — currently a skeleton) and the AVX2 intrinsics in `crates/kyberlib/src/avx2/`. We assume "wait, why does the assembly exist?" will surface. |
| **Supply chain** | `Cargo.toml` deps, the `cargo-vet` import set, the SHA-pinning of GitHub Actions in `.github/workflows/*`, the SLSA L3 + cosign release pipeline. |

### 3.2 Out of scope

| Area | Why |
|------|-----|
| Hardware fault attacks | Out of band; vendor-recommendation territory. |
| FIPS 140-3 certification | Not a goal — the `fips` feature delegates to `aws-lc-rs` for customers needing CMVP. |
| ML-KEM-512 / ML-KEM-1024 | Not yet wired in this build (#130b). Tracked separately. |
| `kyberlib-cose` | Skeleton only at audit time. |
| Round 3 KAT corpus | Intentionally invalid after the FIPS 203 migration; kept for archival regression. |

### 3.3 Methodology preference

We prefer the audit to:

1. **Start from the README + SECURITY.md + ADRs.** Map our claims
   onto the source.
2. **Read the three FIPS 203 patches** (`417595a` / `27e4b6b` /
   `b0f3bfb`) and their corresponding evidence document
   (`doc/patches/phase-2b-evidence.md`).
3. **Spot-check the KyberSlash audit** (ADR 0003 + the static
   guard at `scripts/kyberslash-guard.sh`).
4. **Re-run the ACVP harness** locally and reproduce 60 / 60.
5. **Examine** the typed-key API (`crates/kyberlib/src/ml_kem.rs`)
   and the X25519MLKEM768 hybrid (`crates/kyberlib-hybrid/src/lib.rs`).
6. **Flag any unsafe block in `crates/kyberlib/src/avx2/`** that
   lacks a `// SAFETY:` justification, even if the code is otherwise
   correct.
7. **Re-test under `cargo +nightly miri`** if practicable.
8. **Report** in the format described in §4.

We are open to alternate methodology if you propose better.

## 4. Deliverables

| Item | Required? |
|------|-----------|
| Findings report in Markdown or PDF, ≤ 60 pages | Yes |
| One section per finding with: severity (Critical/High/Medium/Low/Info), CVSS 3.1 score, affected files + lines, reproduction steps, suggested remediation | Yes |
| Executive summary suitable for inclusion in our README | Yes |
| Right to publish the report under MIT or CC-BY-4.0 | Yes — with embargo until we remediate Critical / High |
| Re-verification round after remediation (within 30 days of fixes landing) | Yes |
| Verbal Q&A session with the maintainer (1 h) | Yes |
| Public attestation (LinkedIn / blog post) at our option | Yes |

We do **not** require:

* SOC2 / ISO27001-style management findings.
* Penetration testing of any external service.
* Source-code obfuscation review (the repo is intentionally
  readable).

## 5. Timeline

* **RFP sent:** `<TBD>` (target: within 30 days of this commit
  landing on main).
* **Quote deadline:** RFP send date + 14 days.
* **Vendor selected:** RFP send date + 21 days.
* **Audit starts:** `<TBD>` (target start date).
* **Draft report:** start + 3 weeks.
* **Final report:** draft + 2 weeks (after maintainer fact-check).
* **Remediation re-verify:** within 30 days of remediation
  commits landing.
* **v1.0.0 tag:** after re-verify clean.

## 6. Budget guidance

* **Indicative cap:** USD `<TBD>` (recommended USD 40 000 – 80 000
  per the COMPARISON.md research; tier-1 vendors quote toward the
  high end).
* **Payment terms:** `<TBD>` (suggested: 30 % on contract,
  40 % on draft report, 30 % on final + re-verify).
* **Pricing model:** preferred fixed-price for the scope above;
  T&M acceptable for the re-verify round.
* **Travel / on-site:** not required.

## 7. Candidate vendors (alphabetical)

| Vendor | Why we're considering them |
|--------|-----------------------------|
| **Cryspen** | Built libcrux-ml-kem; deep ML-KEM expertise; some prior bugs (eprint 2026/192) found in their verified code by Symbolic Software, which they remediated. |
| **Cure53** | Strong Rust audit track record; well-known for clear reports. |
| **NCC Group — Cryptography Services** | Top-tier crypto practice; previous PQC reviews include audit work for AWS-LC FIPS 3.0. |
| **Quarkslab** | Strong on side-channel work; consistently good crypto-implementation audits. |
| **Symbolic Software** | Found bugs in libcrux-ml-kem (eprint 2026/192, Feb 2026); demonstrates ability to find subtle issues in verified code. |
| **Trail of Bits** | Broad Rust + cryptography expertise; published methodology in Manticore + their CryptoTrail series. |

We will send this RFP to **2–3** of the above. We will not run a
formal competitive bid — we'd rather pick the team with the
strongest ML-KEM-specific track record.

## 8. Materials package

See the companion `MATERIALS.md` for the full set of links,
commit SHAs, and pointers we ship to the chosen vendor on contract
signing.

## 9. Communications

* **Primary channel:** dedicated `audits/<vendor>` private GitHub
  repository, shared with the auditor's named team.
* **Findings repository:** vendor's preference; we mirror to the
  private repo above.
* **Slack / Matrix:** not preferred (audit work deserves async
  considered responses).
* **Calls:** kick-off (1 h), draft-report walk-through (1 h),
  final + remediation review (1 h). All recorded with consent.

## 10. Confidentiality + IP

* The kyberlib source is dual MIT / Apache-2.0; no NDA is required
  to read it.
* The audit *report* is licensed back to the kyberlib project at
  CC-BY-4.0 or MIT-equivalent — we want to publish it.
* Findings that touch *dependencies* (e.g. `x25519-dalek`, `rand`,
  `zeroize`) follow standard responsible-disclosure to the
  upstream maintainer first, with embargo as required.

## 11. Acceptance

Maintainer signs this RFP as exhibit A to the master engagement
contract once a vendor accepts. The vendor counter-signs after
quote acceptance. Any changes to scope after signing require
written agreement; budget impact agreed in advance.

---

**Maintainer point-of-contact:** `<TBD name and email>`
**Date prepared:** _(see git log of this commit)_
**Tracking issue:** [#177](https://github.com/sebastienrousseau/kyberlib/issues/177)
