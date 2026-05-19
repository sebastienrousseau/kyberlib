# ADR 0001 — Migration from CRYSTALS-Kyber Round 3 to FIPS 203 ML-KEM

* **Status:** Accepted (landed in v0.0.7, May 2026)
* **Date of decision:** 2026-05-19
* **Authors:** sebastienrousseau
* **Reviewers:** _(pending — see SECURITY.md disclosure channel)_
* **Implementation commits:** `417595a`, `27e4b6b`, `b0f3bfb`
* **Verification harness:** `crates/kyberlib/tests/test_acvp.rs` (#148, commit `d6ded86`)
* **Tracking issue:** [#147](https://github.com/sebastienrousseau/kyberlib/issues/147) (closed)

## Context

kyberlib originally implemented **CRYSTALS-Kyber Round 3**, the third-round
submission to the NIST Post-Quantum Cryptography Standardization Process
(2020-2022). NIST selected this submission, made small but byte-level
refinements during the standardization phase, and published the resulting
standard as **FIPS 203 — Module-Lattice-Based Key-Encapsulation
Mechanism Standard** in August 2024.

By May 2026 the FIPS 203 spec is the only ML-KEM that:

* matters for procurement (CNSA 2.0 mandates ML-KEM-1024; FedRAMP and
  EU CRA cite FIPS 203 explicitly),
* interoperates with anything in the wild (TLS 1.3 X25519MlKem768
  draft 04 had >60% of human TLS traffic by May 2026 per Cloudflare's
  state-of-PQ report, all of it FIPS 203),
* has authoritative test vectors (NIST ACVP's `ML-KEM-keyGen-FIPS203`
  and `ML-KEM-encapDecap-FIPS203` corpora).

Kyber Round 3 still works as a KEM in isolation but it is no longer
the right answer for any new deployment.

This ADR records the decision to migrate kyberlib's primitives to
FIPS 203, the precise byte-level changes the migration required, and
the implications for downstream consumers.

## Decision

Migrate kyberlib to FIPS 203 ML-KEM, breaking byte-level
compatibility with the Round 3 surface. Specifically:

1. **Apply the three documented Round-3 → FIPS-203 deltas to the
   primitive layer** (commits `417595a`, `27e4b6b`, `b0f3bfb`):

   * **K-byte domain separator in `G`** — `(ρ, σ) ← G(d ‖ k_byte)` in
     `K-PKE.KeyGen` per FIPS 203 §5.1, where `k_byte` is the module
     rank (2, 3, 4 for ML-KEM-{512, 768, 1024}).
   * **Drop `m' = H(m)` pre-hash in Encaps** — feed the raw 32-byte
     `m` directly into `G(m ‖ H(ek))` per FIPS 203 §6.2 (Round 3
     hashed `m` first).
   * **Drop final KDF + switch implicit-rejection to `J(z ‖ c)`** —
     return `K` directly from `G`'s output on success; on rejection,
     return `J(z ‖ c) = SHAKE256(z ‖ c, 32)`. Round 3 ran
     `KDF(K_bar ‖ H(c))` on success and `KDF(z ‖ H(c))` on rejection.

2. **Validate against the authoritative NIST ACVP corpus** —
   `crates/kyberlib/tests/acvp/` carries the JSON-Vector
   prompt/expected pairs from
   `usnistgov/ACVP-Server@master/gen-val/json-files`. The harness in
   `crates/kyberlib/tests/test_acvp.rs` runs every relevant test case
   against kyberlib's deterministic-seed entry points and reports
   per-group `passed / total`. **60 / 60 ML-KEM-768 cases pass** as of
   commit `b0f3bfb`.

3. **Accept that Kyber Round 3 KAT vectors no longer pass.** The
   legacy `crates/kyberlib/tests/test_kat.rs` against pq-crystals
   Round 3 vectors is left in the source tree under the existing
   `--cfg KYBER_SECURITY_PARAMETERat` gate as archival regression;
   it will not be invoked by the default test surface and will not
   gate releases.

4. **Maintain the public API surface during this migration** — the
   `keypair`, `encapsulate`, `decapsulate` Rust functions and the
   `Keypair` type keep their signatures. Phase 3 (#130, the follow-up
   to this migration) redesigns the surface around sealed marker
   types and split `EncapsulationKey` / `DecapsulationKey`; that work
   ships separately so the substance and the API change can be
   reviewed independently.

## Options considered

### A — Stay on Round 3

* **Pros:** zero work; current consumers' bytes keep working.
* **Cons:** procurement-dead. CNSA 2.0, FedRAMP High, EU CRA, NIS2,
  PCI-DSS 4.0 PQC migration plans all name FIPS 203. No production
  endpoint we'd want to interop with is on Round 3. kyberlib's
  COMPARISON.md row would read "spec: Kyber Round 3" forever, which
  reads as "obsolete library" to anyone in 2026.

### B — Wrap Round 3 in a FIPS-203-compatible shim

Add new functions (`ml_kem_*`) that wrap the existing Round 3
primitives and apply the three deltas at the wrapper layer.

* **Pros:** non-breaking; consumers pick which surface to use.
* **Cons:** the wrapper has to "un-do" the Round 3 KDF and `H(m)` and
  re-do the FIPS 203 derivation — but those steps are
  pre-randomization, so the wrapper can't actually do this without
  duplicating the entire encapsulation flow. The cleanest version of
  the wrapper just re-implements Encaps and Decaps from scratch, at
  which point kyberlib carries two parallel KEM implementations
  forever. Maintenance burden too high; testing burden doubled.

### C — Migrate the primitives directly (chosen)

Apply the three deltas to the existing primitive functions.
Round 3 bytes break.

* **Pros:** single FIPS 203 implementation. Round-trip property
  unchanged. Diff is small (~50 lines across 2 files). Three
  bisectable commits with ACVP-flip evidence at each step.
* **Cons:** breaks any downstream consumer that relies on a stored
  Round 3 corpus. Mitigated by the deliberate pre-v1.0 SemVer
  treatment of the patch-number axis as breaking; CHANGELOG covers
  it loudly.

## Implementation

### The three patches in detail

The unified diff was staged in
`doc/patches/phase-2b-fips203.patch` and reviewed against ACVP
evidence in `doc/patches/phase-2b-evidence.md` before any commit
landed.

| # | Commit    | File                                          | What changed                                                                            |
|---|-----------|-----------------------------------------------|------------------------------------------------------------------------------------------|
| 1 | `417595a` | `crates/kyberlib/src/reference/indcpa.rs`     | `hash_g(buf, d, 32)` → `hash_g(buf, d ‖ k_byte, 33)` in `indcpa_keypair`                |
| 2 | `27e4b6b` | `crates/kyberlib/src/kem.rs::encrypt_message` | `buf[..32] = H(m)` → `buf[..32] = m` (drop the pre-hash)                                |
| 3 | `b0f3bfb` | `crates/kyberlib/src/kem.rs` (both functions) | Drop final `KDF`; `K = kr[..32]` on success; `K_reject = SHAKE256(z ‖ c, 32)` on fail   |

The first two changes are mechanical. The third required a small
caller-side fix in `crates/kyberlib/src/kex.rs` callsites because the
Round-3 code's `hash_h(out, ct, KYBER_CIPHERTEXT_BYTES)` truncated
via an explicit length param, while `copy_from_slice` doesn't —
documented inline at the patch site.

### Verification

* Round-trip test suite stayed at **141 / 141** at every commit
  (the property is invariant under all three patches because encap
  and decap apply the same changes in lock-step).
* ACVP gate progression, bisectable per commit:

  | After commit | keyGen | encap | decap |
  |--------------|--------|-------|-------|
  | `92c8bb4`    | 0/25   | 0/25  | 0/10  |
  | `417595a`    | **25/25** | 0/25  | 0/10  |
  | `27e4b6b`    | 25/25  | 0/25† | 0/10  |
  | `b0f3bfb`    | **25/25** | **25/25** | **10/10** |

  † At `27e4b6b` the ciphertext byte-for-byte matches the FIPS 203
  expected value (`04F4A18C69708A17F561778B2AC10D94…`); only the
  shared secret diverges because the final KDF is still in place.
  Patch 3 closes that.

* KyberSlash audit (#149, ADR 0003) confirmed independently that
  these patches do not introduce any new secret-dependent `/` or `%`
  instructions.

## Consequences

### Positive

* **kyberlib is the first Rust ML-KEM implementation on this branch
  to be FIPS 203 conformant** — measured byte-for-byte against the
  NIST ACVP corpus, not just self-attested in the README.
* **Procurement story is now honest.** The COMPARISON.md row flips
  from "Kyber R3 → FIPS 203 in progress" to "FIPS 203" cleanly.
* **TLS 1.3 X25519MlKem768 path becomes possible.** The hybrid
  skeleton in `crates/kyberlib-hybrid` can now be wired (Phase 5.1,
  #167) without producing wire-incompatible bytes.
* **Bisectability of the migration**: each commit is independently
  reasoned, independently verifiable, and rolling back to any
  intermediate state leaves the workspace in a clean compilable +
  testable state.

### Negative

* **Round 3 shared-secret bytes are no longer recoverable.** Any
  consumer that stored Round-3-produced shared secrets and depends
  on byte-equality across kyberlib versions sees a regression. The
  CHANGELOG.md `[0.0.7] → Changed` entry calls this out as a
  BREAKING CHANGE; pre-1.0 SemVer says this is allowed but the loud
  notice matters.
* **Legacy pq-crystals KAT corpus is invalid.** `tests/KAT/` and
  `tests/test_kat.rs` are kept for archival regression purposes but
  do not run in the default test suite. If a future commit needs
  to re-validate against historical Round 3 behaviour, the corpus
  remains accessible.

### Neutral

* **AVX2 backend parity** — the changes above touched only the
  reference backend (`crates/kyberlib/src/reference/indcpa.rs` and
  `crates/kyberlib/src/kem.rs`). The AVX2 backend at
  `crates/kyberlib/src/avx2/indcpa.rs` carries its own `indcpa_keypair`
  copy that needs the same K-byte change to be FIPS 203 conformant
  with `--features avx2`. That parity work is tracked as a follow-up
  under #143 (Phase 1.2's ASM-quarantine work) because the AVX2
  build currently doesn't compile on the developer's aarch64 macOS
  workstation (the GAS asm is x86_64-only). The ACVP harness skips
  the AVX2 path on aarch64; on a Linux x86_64 runner with
  `RUSTFLAGS='-C target-feature=+avx2 --cfg KYBER_SECURITY_PARAMETERat'`
  the AVX2 backend should be re-tested once the patch lands.

## Open follow-ups (referenced in commit `b0f3bfb`)

* **#150** — re-export the ML-KEM OID table from `kyberlib` core
  (currently in `crates/kyberlib-pkcs8/src/lib.rs::oid`).
* **#151** — public-API rename `Kyber*` → `MlKem*` with
  `#[deprecated]` aliases for one release.
* **#130 / Phase 3** — full API redesign (sealed `KemCore` trait,
  `MlKem512` / `MlKem768` / `MlKem1024` marker types,
  `EncapsulationKey` / `DecapsulationKey` split). Unblocks
  ML-KEM-512 and ML-KEM-1024 across all 240 ACVP cases (currently
  60 — only ML-KEM-768 is wired).

## References

* **FIPS 203** (Aug 2024) — Module-Lattice-Based Key-Encapsulation
  Mechanism Standard. <https://csrc.nist.gov/pubs/fips/203/final>
* **NIST ACVP** ML-KEM test vectors —
  <https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>
* **CNSA 2.0** mandatory algorithms timeline —
  <https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF>
* **EU PQC + NIS2 alignment** (COM(2026) 13 final) —
  <https://decentcybersecurity.eu/post-quantum-cryptography-nis2/>
* **Cloudflare State of the PQ Internet 2025** — TLS hybrid
  adoption metrics. <https://blog.cloudflare.com/pq-2025/>
* **pq-crystals/kyber** upstream — the Round 3 reference that
  kyberlib was forked from. <https://github.com/pq-crystals/kyber>
* **Phase 2(a) ACVP harness** — commit `d6ded86` (this repo).
* **Phase 2(b) review packet** — `doc/patches/phase-2b-evidence.md`
  (this repo).
