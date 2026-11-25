# kyberlib vs. the 2026 Rust ML-KEM landscape

> Last Updated: 2026-11-07 (kyberlib column, for v0.0.16). The other
> columns were gathered in May 2026 and have not been re-verified.

> Audit-quality comparison of kyberlib against the four other Rust ML-KEM
> implementations that are realistically deployable in 2026. Updated for
> the v0.0.7 enterprise-upgrade cut. Honest about kyberlib's current
> gaps — the table is intended to help procurement teams pick the
> right crate, not to oversell ours.

## Scope

This document compares production-grade Rust crates that implement (or
wrap) FIPS 203 ML-KEM. Crates that are explicitly experimental, draft,
or not on crates.io are listed for awareness but not scored.

| Crate                | Latest (May 2026) | Owner                     | Approach                          |
|----------------------|-------------------|---------------------------|-----------------------------------|
| **kyberlib**         | 0.0.16            | sebastienrousseau         | Pure Rust, no `unsafe`; optional AWS-LC FIPS backend |
| **RustCrypto/ml-kem**| 0.3.0-rc.0        | RustCrypto                | Pure-Rust spec-true                |
| **libcrux-ml-kem**   | 0.0.8             | Cryspen / PQCP            | Pure-Rust, F* + hax verified       |
| **pqcrypto-kyber**   | 0.8.x             | rustpq                    | C bindings (PQClean Kyber R3)      |
| **oqs / oqs-rs**     | 0.10.x            | Open Quantum Safe         | C bindings to liboqs               |
| **aws-lc-rs (ML-KEM)** | 1.10.x          | AWS                       | Rust bindings to AWS-LC FIPS 3.0   |

## Headline matrix

| Capability                              | kyberlib (v0.0.16)           | RustCrypto/ml-kem         | libcrux-ml-kem            | pqcrypto-kyber             | oqs-rs               | aws-lc-rs (ML-KEM)     |
|----------------------------------------|------------------------------|----------------------------|----------------------------|-----------------------------|----------------------|------------------------|
| **Spec**                                | FIPS 203 | FIPS 203                  | FIPS 203                   | Kyber R3 only               | Both (parameterised) | FIPS 203               |
| **NIST ACVP vectors**                   | 180/180 (ML-KEM-512, -768, -1024) | Passing                   | Passing                    | n/a (R3)                    | Passing              | Passing (CMVP-listed)  |
| **Pure Rust**                           | ✅                            | ✅                          | ✅                          | ❌ (C FFI)                  | ❌ (C FFI)            | ❌ (C FFI to AWS-LC)    |
| **`#![forbid(unsafe_code)]` core**      | ✅ every build | ✅                          | ✅ (verified backends)      | n/a                          | n/a                  | n/a                    |
| **Formal verification**                 | ❌ (libcrux backend planned, #171) | ❌                          | ✅ (F* + hax)              | ❌                           | ❌                    | Partial (SAW for some primitives) |
| **Third-party audit**                   | ❌ (gating v1.0; RFP ready) | ❌                          | ❌ (verified ≠ audited; bugs in eprint 2026/192) | ❌ (unmaintained)          | ❌ ("not for production") | FIPS 140-3 (CMVP, 2025) |
| **MSRV**                                | 1.89 | 1.74                       | 1.81                       | older                       | varies               | 1.71                   |
| **`no_std` (+ `alloc`)**                | ✅                            | ✅                          | ✅                          | partial                      | ❌                    | ❌                      |
| **WASM (`wasm32-unknown-unknown`)**     | ✅ (`kyberlib-wasm`)          | ✅                          | ✅                          | ❌                           | partial              | ❌                      |
| **AVX2**                                | ❌ (via libcrux backend, #171; in-tree AVX2 removed, ADR 0009) | partial                    | ✅                          | C asm                       | C asm                | ✅                      |
| **NEON / AArch64**                      | ❌ (via libcrux backend, #171 / #172) | partial                    | ✅                          | C asm                       | C asm                | ✅                      |
| **AVX-512**                             | ❌                            | ❌                          | roadmap                    | ❌                           | partial              | ✅                      |
| **SVE2 / SME**                          | ❌                            | ❌                          | ❌                          | ❌                           | ❌                    | ❌                      |
| **Constant-time validation**            | dudect harness wired; KyberSlash CI guard | post-CVE-2026-22705 audit  | hax `secret_independence` | n/a (R3)                    | ❌                    | NIST-vetted             |
| **`Zeroize` / `ZeroizeOnDrop`**         | ✅ unconditional              | ✅ feature-gated            | ✅                          | ❌                           | partial              | ✅                      |
| **`!Copy` secret types**                | ✅ | ✅                          | ✅                          | ❌                           | ❌                    | ✅                      |
| **Trait-based generic API**             | ✅ (`KemCore`) | ✅ (`KemCore`)              | ✅                          | macro-based                  | trait-ish            | ✅                      |
| **HPKE drop-in via `kem` traits**       | planned (#155) | ✅                          | partial                    | ❌                           | ❌                    | partial                |
| **Hybrid X25519MLKEM768**               | ✅ + SecP256r1/SecP384r1 + X-Wing (`kyberlib-hybrid`, unpublished) | ❌ (separate crate)         | ✅                          | ❌                           | ✅                    | partial                |
| **PKCS#8 / SPKI / PEM**                 | ✅ RFC 9935 + encrypted PKCS#8 (`kyberlib-pkcs8`, unpublished) | ✅                          | ✅                          | ❌                           | ❌                    | ✅                      |
| **COSE / CBOR**                         | planned (#169)               | ❌                          | ❌                          | ❌                           | ❌                    | ❌                      |
| **`fuzz/` corpus**                      | ✅ (4 targets)                | ✅                          | ✅                          | upstream                     | upstream             | upstream                |
| **Miri in CI**                          | ✅ (per-PR subset + weekly full sweep) | ✅                          | ✅                          | ❌                           | ❌                    | ❌                      |
| **SBOM (CycloneDX)**                    | ✅ 1.5                        | ❌                          | ❌                          | ❌                           | ❌                    | ❌                      |
| **CBOM (CycloneDX 1.6, `cryptoProperties`)** | ✅                       | ❌                          | ❌                          | ❌                           | ❌                    | ❌                      |
| **SLSA L3 attestation**                 | ✅ release.yml | ❌                          | partial                    | ❌                           | ❌                    | ❌                      |
| **Sigstore / cosign signing**           | ✅ release.yml | ❌                          | ❌                          | ❌                           | ❌                    | ❌                      |
| **`cargo-vet` audit graph**             | imports from 7 orgs | upstream                   | upstream                   | ❌                           | ❌                    | upstream                |
| **`cargo-deny` policy**                 | ✅                            | ✅                          | ✅                          | partial                      | ❌                    | ✅                      |
| **FIPS 140-3 path**                     | ✅ `fips` feature (AWS-LC module) | ❌                       | ❌                          | ❌                           | ❌                    | ✅ (CMVP "in process")  |
| **License**                             | MIT OR Apache-2.0            | MIT OR Apache-2.0          | Apache-2.0                 | MIT OR Apache-2.0           | MIT                  | ISC AND Apache-2.0     |
| **crates.io downloads / month (May 2026)** | new | ~515k                      | ~85k                       | ~22k (declining)             | ~12k                 | ~3.2M (whole crate)    |

## Picking the right crate for your use case

### "I need FIPS 140-3"

Use **`aws-lc-rs`** with the ML-KEM feature, or kyberlib's `fips`
feature (since 0.0.12), which runs kyberlib's typed API inside the
AWS-LC FIPS module. Check certificate coverage for your build
([`FIPS.md`](./FIPS.md)).

### "I need pure Rust and formal verification"

Use **`libcrux-ml-kem`**, with eyes open: Symbolic Software's
2026-02 audit found three bugs in the verified surface (eprint
2026/192). Verification is a strong signal, not a guarantee.

### "I need pure Rust and the broadest API ecosystem"

Use **`RustCrypto/ml-kem`**. It's the standard Rust trait API,
which means HPKE, hybrid-KEM wrappers, TLS providers, and HSM
bridges already integrate against it. Caveat: ml-dsa (its sibling)
shipped CVE-2026-22705 (timing leak) in Feb 2026 — RustCrypto is
solid but not infallible.

### "I'm doing research / prototyping with old Kyber R3 vectors"

Use **`pqcrypto-kyber`** if you specifically need Round 3
compatibility for backwards regression work, but note the crate is
marked unmaintained.

### "I want what kyberlib will offer once v0.0.7 → v1.0 closes out"

A coherent multi-crate workspace:

* `kyberlib`         — safe pure-Rust core (`#![forbid(unsafe_code)]` in every build)
* `kyberlib-hybrid`  — X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
* `kyberlib-pkcs8`   — PKCS#8 / SPKI / PEM encoding for X.509
* `kyberlib-wasm`    — wasm-bindgen JS shim
* `--features fips`  — delegates to `aws-lc-rs` for CMVP-listed crypto
* `--features verified` — delegates to `libcrux-ml-kem` for verified crypto

Plus an enterprise tooling layer (SBOM, CBOM, cargo-vet imports, fuzz
corpus, Miri, dudect, SLSA L3, cosign keyless signing) that none of
the alternatives currently ship as a complete package.

That's the target v1.0 picture. v0.0.7 is the structural foundation;
the cryptographic substance follows the Phase 2(b) FIPS 203 patch and
the third-party audit (#177) gating v1.0.

## Methodology

* "Passing" / "0/60 pass" for ACVP comes from running each crate's
  test suite against the NIST ACVP-Server `gen-val/json-files/ML-KEM-*-FIPS203`
  corpus (commit `usnistgov/ACVP-Server@master`, SHAs in
  `crates/kyberlib/tests/acvp/SHA256SUMS`).
* "Audit" only counts third-party security audits with published
  reports. Self-audits are not counted.
* "FIPS 140-3" only counts modules with a CMVP certificate
  (validated, or "in process" with a published submission).
* Download numbers from crates.io's monthly stats for May 2026.

## Updates

This document is regenerated each time a new major release ships,
or when any of the compared crates publishes a substantive change.
Open an issue if you spot a stale or incorrect claim — most rows
are point-in-time snapshots.
