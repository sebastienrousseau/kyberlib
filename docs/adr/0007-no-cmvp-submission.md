# ADR 0007 — No CMVP submission for kyberlib itself

* **Status:** Accepted
* **Date of decision:** 2026-11-07
* **Authors:** sebastienrousseau
* **Tracking issue:** [#179](https://github.com/sebastienrousseau/kyberlib/issues/179)
* **Related:** [ADR 0006](./0006-fips-facade.md) (`fips` backend),
  [`docs/FIPS.md`](../FIPS.md)

## Context

Regulated users need cryptography from a module validated under FIPS 140-3
by NIST's Cryptographic Module Validation Program (CMVP). Issue #179 asked
whether kyberlib should submit its own pure-Rust ML-KEM for validation, and
recorded the maintainer's assessment: a submission is a multi-year,
six-figure undertaking. A validation also covers one module build in named
operational environments, so it would freeze code that is still pre-1.0
(see `docs/RELEASE-1.0-CHECKLIST.md`).

kyberlib already offers a route for these users: since v0.0.12 the `fips`
feature runs the typed ML-KEM API inside the AWS-LC FIPS module through
`aws-lc-rs`, keeping kyberlib's API and key formats (`docs/FIPS.md`).

## Decision

kyberlib will not be submitted for CMVP validation. Users who must use a
validated module enable the `fips` feature, or call a validated module such
as AWS-LC directly. kyberlib documents what runs inside the module and what
does not, and never claims a certificate it does not hold.

## Consequences

* The pure-Rust backend stays free to change before 1.0.
* Certificate coverage of a `fips` build depends on the AWS-LC module
  version and the user's operational environment; `docs/FIPS.md` lists what
  the user must check and record.
* Revisit only if a sponsor funds a submission after v1.0.0, when the code
  is frozen; that would be a new ADR superseding this one.
