# ADR 0003 — KyberSlash audit

* **Status:** Accepted (audit clean as of 2026-05-19, commit `b0f3bfb`)
* **Date:** 2026-05-19
* **Authors:** sebastienrousseau
* **Reviewers:** _(pending — see SECURITY.md disclosure channel)_
* **Tracking issue:** [#149](https://github.com/sebastienrousseau/kyberlib/issues/149)

## Context

**KyberSlash 1 & 2** are a class of timing side-channel attacks on
Kyber / ML-KEM disclosed by Daniel J. Bernstein et al. in late 2023
([eprint 2023/1933](https://eprint.iacr.org/2023/1933), formalised in
TCHES 2025).

Both attacks exploit the same compiler/CPU pathology: when the
reference implementation uses the C operator `/` or `%` on a
secret-derived integer with constant divisor `q = 3329`, the compiler
emits a hardware `udiv` / `sdiv` instruction. On many widely-deployed
CPUs (Cortex-M3/M4/M7, parts of Cortex-A, some older Atom, etc.) the
hardware division unit takes a **variable number of cycles depending
on the value of the dividend**. That timing signal leaks the secret
key. KyberSlash 2 recovers the long-term key in minutes from local
measurements; KyberSlash 1 in hours.

The pq-crystals reference implementation was patched in late 2023 by
replacing every secret-dependent `/` and `%` with a Barrett-style
multiply-and-shift approximation:

```
DIV(x, q) ≈ (x * a) >> e   where a / 2^e ≈ 1 / q
```

The Barrett constants for ML-KEM are documented in pq-crystals'
patch series; they cover the compression hot path (where the bug
lived) without introducing a 64-bit intermediate.

This ADR documents the audit kyberlib performed against the same
patch class as part of Phase 2.3 of the v0.0.7 enterprise upgrade,
and records the defence-in-depth gate added to keep the audit live.

## Audit

### Method

1. `grep` for `/` and `%` operators in every source file under
   `crates/kyberlib/src/`.
2. For each hit, classify the divisor:
   - **Compile-time constant** (e.g. `KYBER_N / 8`, `KYBER_Q + 1`
     inside a `const` expression) → safe.
   - **Public-length divisor on public value** (e.g.
     `outlen / SHAKE256_RATE`, `(x + 4) % 5` for Keccak step
     indices, `buflen % 3` for rejection-sampling buffer
     management) → safe.
   - **Secret-derived dividend with `q = 3329` divisor** → the
     KyberSlash class.

3. For each hit in the third class, verify it is a Barrett-style
   multiply-and-shift instead of a literal `/` or `%`.

### Findings

#### Reference backend (`crates/kyberlib/src/reference/`)

| Site                                      | Form                                | Verdict |
|-------------------------------------------|-------------------------------------|---------|
| `poly.rs::poly_compress` (d ∈ {4, 5})     | `tmp *= 315; tmp >>= 20`            | Barrett ✓ |
| `poly.rs::poly_compress` (d ∈ {10, 11})   | (via `polyvec_compress`)            | Barrett ✓ |
| `poly.rs::poly_tomsg`                      | `t.wrapping_mul(80635); t >>= 28`  | Barrett ✓ |
| `poly.rs::poly_decompress`                 | `(x * KYBER_Q + 8) >> 4` etc.       | Shift only (power-of-2 divisor) ✓ |
| `poly.rs::poly_tobytes`                    | `>> 8`, `<< 4`                      | Shift only ✓ |
| `poly.rs::poly_frommsg`                    | `KYBER_Q.div_ceil(2)`               | Compile-time const ✓ |
| `polyvec.rs::polyvec_compress` (k=2,3)    | `tmp *= 20642679; tmp >>= 36`       | Barrett ✓ |
| `polyvec.rs::polyvec_compress` (k=4)      | `tmp *= 20642679; tmp >>= 36`       | Barrett ✓ |
| `reduce.rs::barrett_reduce`               | Dedicated Barrett implementation    | Barrett ✓ |
| `indcpa.rs::gen_matrix` (`buflen % 3`)    | Public-domain index                 | Safe (not secret) ✓ |
| `fips202.rs::shake256_squeezeblocks`      | `outlen / SHAKE256_RATE`            | Public length ✓ |

The comment block at the top of `poly_compress` (lines 36-47) cites
the exact Barrett constants and the input range over which the
approximation is provably correct. The patch was applied upstream
in pq-crystals before this codebase forked, so the bug was never
present in kyberlib.

#### AVX2 backend (`crates/kyberlib/src/avx2/`)

The AVX2 backend uses Intel SIMD intrinsics throughout. There is
**no integer SIMD division instruction** in AVX2 — the only way to
divide is the multiply-and-shift approximation, exactly the Barrett
form. The audit confirmed:

| Site                                | Intrinsic                    | Verdict |
|-------------------------------------|------------------------------|---------|
| `poly.rs::poly_compress` (k=2,3)    | `_mm256_mulhi_epi16` + `_mm256_mulhrs_epi16` | Barrett by SIMD ✓ |
| `poly.rs::poly_compress` (k=4)      | Same multiply-high family    | Barrett by SIMD ✓ |
| `polyvec.rs::polyvec_compress`      | Same multiply-high family    | Barrett by SIMD ✓ |
| `keccak4x.rs` (`(x + 4) % 5`)       | Public Keccak step index     | Safe (not secret) ✓ |

#### Other files

`symmetric.rs`, `kem.rs`, `kex.rs`, `api.rs`, `rng.rs`, `params.rs`,
`macros.rs`, `error.rs` contain no `/` or `%` operations on
secret-derived values. The constants in `params.rs` use compile-
time-evaluated `/` (e.g. `KYBER_POLYVEC_BYTES = KYBER_POLY_BYTES *
KYBER_SECURITY_PARAMETER`).

### Result

kyberlib is **KyberSlash-clean** as of commit `b0f3bfb`. No source
modifications are required.

## Decision

* **Close issue #149 as resolved** with this ADR as the audit
  record.
* **Add a regression guard:** `scripts/kyberslash-guard.sh` greps
  the source tree for forbidden patterns (`/ KYBER_Q`, `% KYBER_Q`,
  and the loose patterns `/ KYBER_Q as` / `% KYBER_Q as`). Wired
  into `Makefile` as `make kyberslash-guard` and into CI as a fast
  gate that fails any PR reintroducing one of those forms.
* **Update `SECURITY.md`:** flip the constant-time guarantee table
  for `poly_compress` / `poly_tomsg` from "audit in progress" to
  "audited and clean (ADR 0003)".
* **Update `scripts/dudect.sh`:** the audit-pending rationale no
  longer applies; the script can transition from "exit 0 with a
  pointer to KyberSlash work" to "run the harness when present".
  The full dudect harness itself remains future work (the
  `dudect-bencher` integration is non-trivial), but the gating
  condition documented in Phase 4.3 is now satisfied.

## Consequences

### Positive

* The Phase 2(b) FIPS 203 patch + the KyberSlash audit together
  remove the two biggest "we're not really conformant or
  side-channel-safe" caveats in kyberlib's documentation.
* CI now enforces the audit going forward — if anyone (including a
  future contributor or a careless `cargo fix --suggestions` run)
  re-introduces a literal `/ KYBER_Q` form, the gate fails before
  the change can merge.
* `dudect` (Phase 4.3) can graduate from "scaffolded" to "wireable"
  in a follow-up commit — the precondition is now met.

### Negative

* The grep gate is a syntactic check, not a semantic one. A
  determined regression could obfuscate the division (e.g. via a
  helper function, or by computing `q` at runtime instead of using
  the constant). The grep is defence-in-depth, not a complete
  proof. The dudect harness, once wired, is the empirical check
  that catches the semantic regression.

### Neutral

* The audit is point-in-time. A new SIMD backend, a new platform
  with different compiler behaviour, or a future spec evolution
  that introduces new compression sites would all require re-
  auditing this same surface. The grep gate covers the regression
  risk for the existing pattern; new patterns need new entries.

## References

* Bernstein et al., "KyberSlash: Exploiting secret-dependent
  division timings in Kyber implementations", eprint 2023/1933,
  TCHES 2025 — <https://eprint.iacr.org/2023/1933>
* Project Eleven, "PQ implementation vulnerabilities Volume 1: A
  RustCrypto side-channel CVE" (CVE-2026-22705, Feb 2026) —
  the same class of bug landed in RustCrypto's `ml-dsa` and was
  caught only after publication. Reinforces the value of a
  regression gate. <https://blog.projecteleven.com/posts/pq-implementation-vulnerabilities-volume-1-a-rustcrypto-side-channel-cve>
* pq-crystals/kyber upstream patch series (the source of the
  Barrett constants `315/2^20` and `20642679/2^36`) —
  <https://github.com/pq-crystals/kyber>
