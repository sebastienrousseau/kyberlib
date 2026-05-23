# Phase 2(b) — FIPS 203 patch review packet

> **Status:** Awaiting cryptographer review. The patches are in
> `phase-2b-fips203.patch` (next to this file). They are **not**
> committed to the source tree — apply with `git apply` only after
> review.
>
> Once approved, the patches should be split into three commits
> (one per logical change) and the legacy Kyber R3 KAT in
> `tests/test_kat.rs` should either be removed or gated on
> `--cfg KYBER_R3_LEGACY` for historical regression.

## What the patches do

Three changes to bring kyberlib's primitives into byte-for-byte
conformance with FIPS 203 (Aug 2024). The diff is in `phase-2b-fips203.patch`;
this document maps each change to its spec citation and its ACVP
flip.

### Patch 1 — K-byte domain separation in `G`

* **Spec:** FIPS 203 §5.1, K-PKE.KeyGen, step 1:
  `(ρ, σ) ← G(d ‖ K_byte)` where `K_byte ∈ {2, 3, 4}` is the
  module rank — 2 for ML-KEM-512, 3 for ML-KEM-768, 4 for
  ML-KEM-1024. This byte was added in the final standard
  specifically as a domain separator between parameter sets.
* **File:** `crates/kyberlib/src/reference/indcpa.rs`, function
  `indcpa_keypair` (was line 224).
* **Round 3 code:**
  ```rust
  hash_g(&mut buf, &randbuf, KYBER_SYM_BYTES);
  ```
* **FIPS 203 code:**
  ```rust
  let mut g_input = [0u8; KYBER_SYM_BYTES + 1];
  g_input[..KYBER_SYM_BYTES].copy_from_slice(&randbuf[..KYBER_SYM_BYTES]);
  g_input[KYBER_SYM_BYTES] = KYBER_SECURITY_PARAMETER as u8;
  hash_g(&mut buf, &g_input, KYBER_SYM_BYTES + 1);
  ```

### Patch 2 — Drop `m' = H(m)` pre-hash in Encaps

* **Spec:** FIPS 203 §6.2, ML-KEM.Encaps_internal, step 2:
  `(K, r) ← G(m ‖ H(ek))` — the raw 32-byte `m` flows directly
  into `G`. Kyber Round 3 hashed `m' = H(m)` first and used `m'`
  in `m`'s place.
* **File:** `crates/kyberlib/src/kem.rs`, function `encrypt_message`
  (was line 87).
* **Round 3 code:**
  ```rust
  hash_h(&mut buf, &randbuf, KYBER_SYM_BYTES);   // buf[..32] = H(m)
  ```
* **FIPS 203 code:**
  ```rust
  buf[..KYBER_SYM_BYTES].copy_from_slice(&randbuf[..KYBER_SYM_BYTES]); // buf[..32] = m
  ```

### Patch 3 — Drop final KDF; switch rejection to `J(z ‖ c)`

* **Spec, success path:** FIPS 203 §6.2, Encaps step 4 / §6.3,
  Decaps step 10. The shared secret `K` is the first half of `G`'s
  output directly. Kyber Round 3 applied a final
  `K = KDF(K̄ ‖ H(c))` over the pre-key plus the ciphertext hash.
* **Spec, failure path:** FIPS 203 §6.3, Decaps step 7+9.
  `K_reject = J(z ‖ c)` where `J = SHAKE256(·, 32)`. Kyber Round 3
  used `K_reject = KDF(z ‖ H(c))` — a different hash (the KDF, not J)
  over a different input (`H(c)`, not `c`).
* **Files:** `crates/kyberlib/src/kem.rs`, functions `encrypt_message`
  (was lines 97-100) and `decrypt_message` (was lines 138-144).
* **Round 3 code (encap tail):**
  ```rust
  hash_h(&mut kr[KYBER_SYM_BYTES..], ct, KYBER_CIPHERTEXT_BYTES);
  kdf(ss, &kr, 2 * KYBER_SYM_BYTES);
  ```
* **FIPS 203 code (encap tail):**
  ```rust
  ss[..KYBER_SHARED_SECRET_BYTES]
      .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);
  ```
* **Round 3 code (decap tail):**
  ```rust
  hash_h(&mut kr[KYBER_SYM_BYTES..], ct, KYBER_CIPHERTEXT_BYTES);
  cmov(&mut kr, &sk[END..], KYBER_SYM_BYTES, fail);
  kdf(ss, &kr, 2 * KYBER_SYM_BYTES);
  ```
* **FIPS 203 code (decap tail):**
  ```rust
  let mut k_reject_input = [0u8; KYBER_SYM_BYTES + KYBER_CIPHERTEXT_BYTES];
  k_reject_input[..KYBER_SYM_BYTES].copy_from_slice(&sk[END..]);
  // ct may be a slice into a longer buffer (kex.rs concatenates payload).
  k_reject_input[KYBER_SYM_BYTES..]
      .copy_from_slice(&ct[..KYBER_CIPHERTEXT_BYTES]);
  let mut k_reject = [0u8; KYBER_SHARED_SECRET_BYTES];
  kdf(&mut k_reject, &k_reject_input,
      KYBER_SYM_BYTES + KYBER_CIPHERTEXT_BYTES);

  ss[..KYBER_SHARED_SECRET_BYTES]
      .copy_from_slice(&kr[..KYBER_SHARED_SECRET_BYTES]);
  cmov(ss, &k_reject, KYBER_SHARED_SECRET_BYTES, fail);
  ```

  Notes:
  - `kdf` is already SHAKE256(·, 32) in the non-90s build path —
    same primitive as FIPS 203's `J`.
  - `cmov` (the existing constant-time conditional move) selects
    between `K̄` (kr) and `K_reject` based on the verify result.

## ACVP evidence

Each patch was applied incrementally and the ACVP harness re-run.
The harness is in `crates/kyberlib/tests/test_acvp.rs` and gated on
`--cfg KYBER_SECURITY_PARAMETERat`; the vectors come from
`crates/kyberlib/tests/acvp/{keyGen,encapDecap}-{prompt,expected}.json`
(NIST ACVP-Server master, SHA-256s checked into `SHA256SUMS`).

| Applied                | keyGen      | encap       | decap       |
|------------------------|-------------|-------------|-------------|
| (baseline, Round 3)    | **0/25 FAIL** | **0/25 FAIL** | **0/10 FAIL** |
| Patch 1 only           | **25/25 OK** | 0/25 FAIL (c ✓, k ✗) | 0/10 FAIL  |
| Patch 1 + Patch 2      | 25/25 OK    | 0/25 FAIL (c ✓, k ✗) | 0/10 FAIL  |
| Patch 1 + 2 + 3        | **25/25 OK** | **25/25 OK** | **10/10 OK** |

After Patch 2 alone the **ciphertext** for tcId 26 matched
exactly (`04F4A18C69708A17F561778B2AC10D94…` against
`04F4A18C69708A17F561778B2AC10D94…`) but the **shared secret** still
diverged because the final KDF stayed in place. Patch 3 closes that
last gap.

After all three patches:

```
ACVP keyGen results:
  ML-KEM-768 keyGen                                    25/25   OK
ACVP encap results:
  ML-KEM-768 encapsulation                             25/25   OK
ACVP decap results:
  ML-KEM-768 decapsulation                             10/10   OK
test result: ok. 3 passed; 0 failed
```

**60 / 60 ML-KEM-768 ACVP cases.** ML-KEM-512 and ML-KEM-1024 are
skipped — the Cargo features for those are still disabled (the
Phase 3 trait redesign in #130 / #153 unlocks them simultaneously).

## Collateral

* `cargo test --workspace`: **141 / 141 still pass** (the integration
  tests under `tests/test_kex.rs` exercised an undocumented
  invariant that `ct` to `decrypt_message` may be longer than
  `KYBER_CIPHERTEXT_BYTES`. The R3 code used `hash_h(..., ct,
  KYBER_CIPHERTEXT_BYTES)` which truncated via the explicit length
  param; `copy_from_slice` in Patch 3 does not, so the patch
  explicitly slices `ct[..KYBER_CIPHERTEXT_BYTES]`. This is in the
  diff and documented inline).
* Legacy `tests/test_kat.rs` (pq-crystals R3 vectors): does **not**
  compile under the current lint set even before the patch (a
  pre-existing `unreachable_pub` violation in `tests/load/mod.rs`).
  Once the patch lands it should either be deleted or gated on
  `--cfg KYBER_R3_LEGACY` for archival regression purposes.
* AVX2 mirror: the patch only touches the reference implementation
  in `src/reference/indcpa.rs`. The AVX2 backend has its own copy
  of `indcpa_keypair` at `crates/kyberlib/src/avx2/indcpa.rs` that
  needs the same K-byte change. Including that diff was out of
  scope because the AVX2 build doesn't compile on aarch64 macOS
  (the GAS asm is x86_64-only). Tracking: a sub-issue under
  #143 / #149.

## Suggested commit split

Once approved, please split into **three** atomic commits so the
ACVP gate transition is bisectable:

1. `fix(crypto): FIPS 203 §5.1 — append k_byte to G(d) for keygen`
   — `crates/kyberlib/src/reference/indcpa.rs`
2. `fix(crypto): FIPS 203 §6.2 — drop m'=H(m) pre-hash in encaps`
   — `crates/kyberlib/src/kem.rs` (encap path)
3. `fix(crypto): FIPS 203 §6.2/§6.3 — drop final KDF; J(z‖c) on rejection`
   — `crates/kyberlib/src/kem.rs` (full encap + decap tail)

Each commit should bear `Refs: #147, #148, #149` and the third
should additionally `Closes: #147`.

## Verification recipe for the reviewer

```sh
# Apply
git apply doc/patches/phase-2b-fips203.patch

# Verify
cargo test --workspace                                       # 141 / 141
RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' \
  cargo test -p kyberlib --test test_acvp -- --nocapture     # 3 / 3 OK
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo deny --all-features check

# When happy, split into 3 commits per the section above and push.
```
