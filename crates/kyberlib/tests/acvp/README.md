# NIST ACVP ML-KEM test vectors

Source: <https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files>

Files in this directory are the authoritative FIPS 203 conformance corpus
maintained by NIST's Automated Cryptographic Validation Protocol (ACVP)
team. They supersede the pq-crystals Kyber-Round-3 KAT vectors that
`tests/KAT/` was built around.

| File | Source path | Purpose |
|------|------------|---------|
| `keyGen-prompt.json` | `ML-KEM-keyGen-FIPS203/prompt.json` | (d, z) seeds for `ML-KEM.KeyGen` |
| `keyGen-expected.json` | `ML-KEM-keyGen-FIPS203/expectedResults.json` | Expected (ek, dk) outputs |
| `encapDecap-prompt.json` | `ML-KEM-encapDecap-FIPS203/prompt.json` | (ek, m) inputs for encap; (c, dk) inputs for decap |
| `encapDecap-expected.json` | `ML-KEM-encapDecap-FIPS203/expectedResults.json` | Expected (c, k) for encap; (k) for decap |

Refresh with `scripts/acvp-refresh.sh` — it re-downloads from the canonical
URLs and re-verifies the SHA-256 of each file against `SHA256SUMS`. The
test harness in `tests/test_acvp.rs` consumes these directly.

## SHA-256

See `SHA256SUMS`. Verify with `shasum -c SHA256SUMS` from inside this
directory.

## Test coverage by `tgId`

| tgId | testType | parameterSet | function                | count |
|------|----------|--------------|-------------------------|-------|
| 1    | AFT      | ML-KEM-512   | keyGen                  | 25    |
| 2    | AFT      | ML-KEM-768   | keyGen                  | 25    |
| 3    | AFT      | ML-KEM-1024  | keyGen                  | 25    |
| 1    | AFT      | ML-KEM-512   | encapsulation           | 25    |
| 2    | AFT      | ML-KEM-768   | encapsulation           | 25    |
| 3    | AFT      | ML-KEM-1024  | encapsulation           | 25    |
| 4    | VAL      | ML-KEM-512   | decapsulation           | 10    |
| 5    | VAL      | ML-KEM-768   | decapsulation           | 10    |
| 6    | VAL      | ML-KEM-1024  | decapsulation           | 10    |
| 7    | VAL      | ML-KEM-512   | decapsulationKeyCheck   | 10    |
| 8    | VAL      | ML-KEM-512   | encapsulationKeyCheck   | 10    |
| 9    | VAL      | ML-KEM-768   | decapsulationKeyCheck   | 10    |
| 10   | VAL      | ML-KEM-768   | encapsulationKeyCheck   | 10    |
| 11   | VAL      | ML-KEM-1024  | decapsulationKeyCheck   | 10    |
| 12   | VAL      | ML-KEM-1024  | encapsulationKeyCheck   | 10    |

**Total: 240 test cases.**

Phase 2(a) only validates the **functional** tests (keyGen + encapsulation +
decapsulation) — 180 cases. The keyCheck tests (60 cases) target
malformed-key acceptance/rejection, which depends on Phase 3's typed-key
work and is deferred.

## What if a group fails

If a parameter set fails to match byte-for-byte, the harness prints the
first divergence per group:

```
FAIL: ml-kem-768 encap tcId 1
  expected k: 4B7B1514...
  observed k: 8FA31E92...
```

This is the diagnostic we need to localise the divergence in
`src/symmetric.rs` (`G`/`H`/`J`/`KDF` calls) and `src/kem.rs` (the
encrypt/decrypt orchestration) against FIPS 203 §6.2–§6.3.
