# Glossary

Terminology used across kyberlib's docs, code comments, and the
FIPS 203 ML-KEM standard. Each entry cross-references the FIPS 203
section where the concept is defined (or the IETF document that
introduces it).

## Algorithms and schemes

**CRYSTALS-Kyber** — The pre-FIPS-203 name for the lattice-based
KEM that NIST standardised in August 2024. kyberlib's public API
moved to the FIPS 203 spelling (`ML-KEM`) in v0.0.7; the legacy
`KYBER_*` constants remain as `#[deprecated]` aliases for migration.

**Fujisaki–Okamoto (FO) transform** — Construction that lifts an
IND-CPA-secure public-key encryption scheme to an IND-CCA-secure
KEM. ML-KEM applies the FO transform to the underlying IND-CPA
scheme (FIPS 203 §6). See also: *implicit rejection*.

**KEM** — Key-Encapsulation Mechanism. A two-party protocol where
the encapsulator produces a ciphertext + shared secret against the
receiver's public key, and the receiver decapsulates the ciphertext
to recover the same shared secret. Distinct from a key-exchange
mechanism in that one party generates the secret unilaterally.

**ML-KEM** — Module-Lattice-based KEM. The FIPS 203 (August 2024)
standardised form of CRYSTALS-Kyber. Three parameter sets ship:
ML-KEM-512, ML-KEM-768, ML-KEM-1024.

## Parameter sets (FIPS 203 §6)

| Set | Module rank `K` | η₁ | η₂ | d_u | d_v | NIST category |
|---|---|---|---|---|---|---|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 1 (≈ AES-128) |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 3 (≈ AES-192) |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 5 (≈ AES-256) |

## Primitives

**Barrett reduction** — Division-free modular reduction technique
that replaces `x mod q` with a multiply-and-shift sequence. Used
throughout kyberlib's `reference` backend to avoid secret-dependent
hardware divide instructions (see ADR 0003 — *KyberSlash audit*).

**Centred binomial distribution (CBD)** — The narrow distribution
from which ML-KEM samples secret-key and noise polynomial
coefficients. `cbd2` samples η = 2 (range −2..=2); `cbd3` samples
η = 3 (range −3..=3). The active sampler is selected per-parameter-
set off `P::ETA1`.

**KDF** — Key-Derivation Function. ML-KEM's KDF is SHAKE-256 with
32-byte output (FIPS 203 §4.2). Replaces Kyber Round 3's separate
KDF and absorb step.

**Montgomery form / Montgomery multiplication** — Modular-arithmetic
representation that turns the modular-reduction cost into a single
multiply-and-shift. kyberlib stores polynomial coefficients in
Montgomery form throughout the NTT pipeline and converts back to
standard form only at message boundaries.

**NTT** — Number-Theoretic Transform. The discrete equivalent of the
FFT over `Z_q`. ML-KEM uses NTT to reduce polynomial multiplication
from O(N²) to O(N log N). The NTT modulus `q = 3329` is chosen so
that the 256th root of unity exists mod q.

**Polyvec** — A vector of `K` polynomials, each over the ring
`Z_q[X] / (X^256 + 1)`. The secret key, public key, and ciphertext-u
component are all polyvecs.

**Polynomial ring** — `R_q = Z_q[X] / (X^N + 1)` with `q = 3329`,
`N = 256`. Every polynomial-arithmetic operation in ML-KEM takes
place in this ring.

**PRF** — Pseudorandom Function. ML-KEM uses SHAKE-256 as its PRF
for noise sampling (under the default features) or AES-256-CTR + SHA-2
(under the deprecated `90s` feature).

**Rejection sampling** — Discarding samples that fall outside the
target distribution. Used in `gen_matrix` to map uniform random
bytes to uniformly random polynomial coefficients mod `q`.

**SHAKE** — A Keccak-based extendable-output function (XOF). ML-KEM
uses SHAKE-128 for matrix expansion and SHAKE-256 for everything
else (PRF / KDF / H / G).

**XOF** — Extendable-Output Function. Distinguished from a hash
function by producing an arbitrary-length output stream from a fixed
input.

## Security properties

**IND-CCA security** — Indistinguishability under Chosen-Ciphertext
Attack. The standard correctness bar for a KEM. ML-KEM achieves
IND-CCA via the FO transform on top of its IND-CPA primitive.

**IND-CPA security** — Indistinguishability under Chosen-Plaintext
Attack. The underlying lattice-based scheme that ML-KEM applies the
FO transform to.

**Implicit rejection** — FIPS 203 §6.3 mechanism: if decapsulation
detects a malformed ciphertext (the FO transform's re-encryption
check fails), the function returns a *pseudorandom* shared secret
instead of erroring. This eliminates the validity-check side channel
that explicit-rejection KEMs have.

**KyberSlash** — A family of timing side-channel attacks (eprint
2023/1933, TCHES 2025) against secret-dependent `/` and `%`
operations modulo `q = 3329`. kyberlib's audit log for KyberSlash
is ADR 0003.

## Engineering

**ACVP** — Automated Cryptographic Validation Protocol (NIST). The
authoritative test-vector format for FIPS 203. kyberlib runs 180
ACVP vectors per CI run: 60 each across ML-KEM-512 / 768 / 1024.

**CMVP** — Cryptographic Module Validation Program (NIST/CSE). The
FIPS 140-3 certification track. kyberlib's `fips` Cargo feature is
the placeholder for delegating to a CMVP-validated backend (aws-lc-rs
or similar — see issue #170).

**dudect** — "Dude, is my code constant time?" — a statistical
timing-leak detector based on Welch's t-test (eprint 2016/1123).
Implemented in `crates/kyberlib/benches/dudect.rs`; the runner is
`scripts/dudect.sh`.

**FIPS 203** — *Module-Lattice-Based Key-Encapsulation Mechanism
Standard*, NIST FIPS 203, August 2024. The standardised form of
ML-KEM. See <https://csrc.nist.gov/pubs/fips/203/final>.

**KAT** — Known-Answer Test. The legacy pq-crystals test-vector
format that pre-dated ACVP. kyberlib's KAT harness lives at
`crates/kyberlib/tests/test_kat.rs`.

**Miri** — Rust's MIR interpreter. Used to detect undefined
behaviour, memory leaks, and data races. kyberlib runs Miri in CI
under `scripts/miri.sh`.

**SLSA L3** — Supply-chain Levels for Software Artifacts, level 3.
The provenance attestation level that kyberlib's release pipeline
produces (via `actions/attest-build-provenance` in `release.yml`).

## Conventions

**OID** — Object IDentifier. Dotted-decimal global identifier per
ITU-T X.660. ML-KEM OIDs are assigned under the
`2.16.840.1.101.3.4.4.*` arc:

| Set | OID |
|---|---|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 |

See `crates/kyberlib/src/oid.rs` for the canonical constants.

**LAMPS** — IETF Limited Additional Mechanisms for PKIX and SMIME.
The working group that produced the ML-KEM `AlgorithmIdentifier`
encoding kyberlib's typed API exposes via [`KemCore::ALGORITHM_ID`].

[`KemCore::ALGORITHM_ID`]: https://docs.rs/kyberlib/latest/kyberlib/trait.KemCore.html#associatedconstant.ALGORITHM_ID
