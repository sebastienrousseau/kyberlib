# Security Policy

## Supported Versions

kyberlib is pre-1.0 software. Only the **latest published `0.0.x` release**
is supported with security fixes. Older `0.0.x` releases are unsupported —
upstream consumers should track the latest patch number.

| Version  | Supported |
|----------|:---------:|
| `0.0.7`  |     ✅    |
| `< 0.0.7`|     ❌    |

A `v1.0.0` will not be tagged until the
[third-party security audit](https://github.com/sebastienrousseau/kyberlib/issues/177)
is complete and all findings have been resolved + re-verified.

## Reporting a Vulnerability

**Please do not file public GitHub issues for security bugs.**

Email <contact@kyberlib.com> with:

- a clear description of the bug,
- the affected version(s) (commit SHA preferred),
- a proof-of-concept or reproducer,
- the impact you've assessed (key recovery, decapsulation oracle, timing
  leak, panic-on-malformed-input, etc.).

We accept reports in English or French.

### Response SLA

- **Initial acknowledgement:** within 48 hours.
- **Triage + severity assignment:** within 7 days.
- **Fix target:** within 30 days for critical issues; longer for low-severity
  issues with appropriate mitigations in place.

### Disclosure

We follow coordinated disclosure. Once a fix is available, we publish:

- a patched release,
- a CVE (if applicable),
- a `RUSTSEC-` advisory in the
  [rustsec/advisory-db](https://github.com/rustsec/advisory-db),
- credit to the reporter (with permission).

## Threat Model

### In scope

kyberlib is a **library implementing the FIPS 203 ML-KEM key encapsulation
mechanism**. It is the responsibility of the caller to:

- supply a cryptographically secure RNG implementing
  `rand_core::CryptoRng + RngCore`,
- handle private keys per their organisation's key-management policy,
- transport ciphertexts and public keys over a channel that provides the
  integrity properties the caller expects.

Within those constraints, kyberlib defends against:

| Class | Coverage |
|---|---|
| Decapsulation oracles | Implicit rejection per FIPS 203 §6.3 (no validity branch) |
| Timing side-channels on `decapsulate` (secret-dependent) | Constant-time `verify` / `cmov` (`src/reference/verify.rs`); KyberSlash-class division audit in progress ([#149][i149]) |
| Memory leaks of secret material | `ZeroizeOnDrop` on `Keypair` and `DecapsulationKey`; non-`Copy` to prevent stack copies |
| Malformed input panics | `try_from` paths return `Err(InvalidInput / InvalidLength)`; never panic on caller-controlled bytes (fuzz-validated in [#159][i159]) |
| Algorithm confusion | OIDs registered per IETF LAMPS draft ([#150][i150]); `Algorithm` ID const string per parameter set |

### Out of scope

- Physical-access attacks (cold-boot, JTAG, fault injection on attacker-held
  hardware).
- Compromise of the host kernel, hypervisor, or RNG source.
- Side-channels exclusive to the **caller's** allocator (e.g. heap layout
  leaks from an arena allocator the caller plugs in).
- Attacks against the operating system's syscall surface used to read
  `/dev/urandom` or equivalent.

## Constant-time Guarantees

kyberlib's CT claims are **per-function** and per-implementation:

| Function | Reference impl | AVX2 impl |
|---|---|---|
| `decapsulate` (in secret key) | ✅ CT | ✅ CT (asm + intrinsics) |
| `encapsulate` (in public key) | ✅ CT | ✅ CT |
| `verify`, `cmov` | ✅ CT (audited bitwise) | ✅ CT |
| `poly_compress`, `poly_tomsg` | ✅ CT (KyberSlash audit clean — [ADR 0003][adr3]) | ✅ CT (SIMD multiply-high, no divide) |
| Key serialisation | ✅ CT in secret bytes | ✅ CT |

[adr3]: https://github.com/sebastienrousseau/kyberlib/blob/main/doc/adr/0003-kyberslash-audit.md

The CT property is validated statistically by `dudect` ([#161][i161]) — see
`scripts/dudect.sh`. KyberSlash 1 & 2 (TCHES 2025) and the analogous
RustCrypto/ml-dsa CVE-2026-22705 (Feb 2026) both proved that "looks CT" is
not enough — every secret-dependent `/` or `%` is audited and replaced with
Barrett-style multiplication. The audit is documented in
[ADR 0003][adr3] and enforced going forward by the
`scripts/kyberslash-guard.sh` static check, which runs in CI on every PR.

## Supply Chain

| Control | Status |
|---|---|
| `cargo audit` | CI gate (Phase 0.8) |
| `cargo deny` | CI gate ([#141][i141]) |
| `cargo vet` | Audit imports from Mozilla, Google, Bytecode Alliance, ISRG, Embark, Fermyon ([#165][i165]) |
| Reproducible build | `vendor-build` CI job using `cargo vendor --offline --locked` |
| `Cargo.lock` committed | ✅ |
| Reusable workflows pinned to commit SHA | ✅ (pre-v0.0.7 used `@main` — fixed in [#141][i141]) |
| SLSA L3 build provenance | Phase 4 ([#163][i163]) |
| Keyless cosign signing | Phase 4 ([#164][i164]) |
| CycloneDX 1.6 CBOM | Phase 4 ([#162][i162]) |
| Signed commits on `main` | Enforced via CI gate ([#141][i141]) |

## FIPS / Regulatory Path

A pure-Rust crate cannot itself be FIPS 140-3 validated. For workloads that
require CMVP listing (FedRAMP High, NIST SP 800-53 control SC-13, CNSA 2.0)
kyberlib offers an **optional `fips` feature** ([#170][i170]) that delegates
all ML-KEM operations to `aws-lc-rs` — the first cryptographic library to
include ML-KEM in a FIPS 140-3 validation (AWS-LC FIPS 3.0, 2025).

For workloads that prefer **formal verification** over FIPS certification,
the **`verified` feature** ([#171][i171]) delegates to `libcrux-ml-kem`
(F\* + hax-verified panic-freedom, functional correctness, and
secret-independence for portable + AVX2 backends). Documented caveat:
Symbolic Software (eprint 2026/192, Feb 2026) found 3 bugs in libcrux's
verified code — verification is necessary, not sufficient.

[i141]: https://github.com/sebastienrousseau/kyberlib/issues/141
[i149]: https://github.com/sebastienrousseau/kyberlib/issues/149
[i150]: https://github.com/sebastienrousseau/kyberlib/issues/150
[i159]: https://github.com/sebastienrousseau/kyberlib/issues/159
[i161]: https://github.com/sebastienrousseau/kyberlib/issues/161
[i162]: https://github.com/sebastienrousseau/kyberlib/issues/162
[i163]: https://github.com/sebastienrousseau/kyberlib/issues/163
[i164]: https://github.com/sebastienrousseau/kyberlib/issues/164
[i165]: https://github.com/sebastienrousseau/kyberlib/issues/165
[i170]: https://github.com/sebastienrousseau/kyberlib/issues/170
[i171]: https://github.com/sebastienrousseau/kyberlib/issues/171

## Safe Harbour

We will not pursue legal action against researchers who:

- act in good faith,
- give us a reasonable window (≥ 90 days, or the published fix date,
  whichever is sooner) before public disclosure,
- avoid privacy violations, data destruction, and service disruption,
- limit testing to keys / inputs they themselves control.
