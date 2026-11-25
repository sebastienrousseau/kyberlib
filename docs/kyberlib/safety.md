# Safety

> Last Updated: 2026-05-22

What kyberlib promises about memory safety, undefined behaviour,
panic-freedom, constant-time execution, and secret handling — and
where the bodies are buried.

## Unsafe code policy

`kyberlib` is `#![forbid(unsafe_code)]` in every build: no feature and no
inner `#[allow]` can lift it. The whole crate (`api`, `hazmat`, `kem`,
`ml_kem`, `paramsets`, `params`, `rng`, `symmetric`, `oid`, `error`,
`reference/*`, and `fips`, which calls the `aws-lc-rs` safe API) is
unsafe-free at compile time.

The AVX2 backend that used to need `unsafe` never compiled and was
removed in v0.0.16 ([ADR 0009](../adr/0009-remove-avx2-backend.md)).

## Constant-time guarantees

ML-KEM is sensitive to timing side channels because the FIPS 203 §6.3
implicit-rejection construction folds the validity check into a
constant-time KDF selection. kyberlib's CT story has three layers:

### 1. Structural — Barrett reduction (ADR 0003)

Every secret-dependent `/` and `%` against `KYBER_Q = 3329` in the
source tree uses a Barrett-style multiply-and-shift sequence inherited
from the pq-crystals upstream. There are no `udiv` / `sdiv` / `urem`
instructions emitted on any secret. The audit log is
[ADR 0003](../adr/0003-kyberslash-audit.md); the regression
gate is `scripts/kyberslash-guard.sh` (annotated safe-site exceptions
are `// kyberslash-guard: safe — <reason>; ADR 0003`).

### 2. Algorithmic — verify + cmov

[`reference/verify.rs`](../../crates/kyberlib/src/reference/verify.rs) implements two
constant-time primitives:

* `verify(a, b, len) -> u8` — returns `1` if `a != b` over `len`
  bytes; runs in time proportional to `len`, not to the
  first-mismatch position.
* `cmov(dest, src, len, b)` — overwrites `dest` with `src` when
  `b != 0`; runs in time independent of `b`.

These drive the FIPS 203 §6.3 implicit-rejection selection in
`kem::decrypt_message` / `kem_dec_generic`.

### 3. Empirical — dudect

[`benches/dudect.rs`](../../crates/kyberlib/benches/dudect.rs) implements two
constant-time benches using Welch's t-test (de Reijke & Bertoni,
eprint 2016/1123):

* `decap_valid_vs_invalid_ct` — decapsulate the same SK against a
  valid CT vs a bit-flipped one. Tests that the implicit-rejection
  KDF runs in indistinguishable time. Current measurement: `max t ≈
  1.4 σ` at 10k samples. The release-gate threshold is ±10 σ.
* `decap_real_pairs` — decapsulate the same SK against a CT that
  authenticates vs one that doesn't (both well-formed). Tests the
  FO transform's branch-prediction invariance. Current measurement:
  `max t ≈ 1.8 σ`.

Run with `cargo xtask dudect quick` (5k samples) or
`cargo xtask dudect full` (200k samples, release-gate threshold).
The script is `scripts/dudect.sh`.

## Panic-freedom

The public surface returns `Result<_, KyberLibError>` for every
fallible operation. Internal `assert!` / `unreachable!` calls exist
only on invariants verified by the type system at the call site:

* `MlKem768DecapKey::decapsulate` calls into `classic::decapsulate`
  which returns `Err(InvalidInput)` on length mismatch. The typed
  wrapper guarantees the length is correct, so an `.expect()` is
  used. The expect message documents the invariant.
* The `match P::DU { 10 | 11 => ..., _ => unreachable!() }` pattern
  in `polyvec_compress_generic`. `MlKemParams` impls fix `DU` to
  `10` or `11` at the trait level; the `_` arm cannot be reached by
  any valid `P: MlKemParams`.

[`tests/test_properties.rs`](../../crates/kyberlib/tests/test_properties.rs) runs
proptest-driven panic-freedom checks against the public surface:

* `encap_key_try_from_slice_total` — any input byte slice either
  parses or returns `InvalidLength`. Never panics.
* `ciphertext_try_from_slice_total` — same.
* `encap_decap_panic_free` — for any pk + ct + sk byte sequences,
  `encapsulate(pk, _)` and `decapsulate(ct, sk)` either return `Ok`
  or `Err(InvalidInput)`. Never panic.
* `ml_kem_768_round_trip_property` — for any 32-byte seed, gen →
  encap → decap yields identical shared secrets on both sides.
* `implicit_rejection_is_total` — for any bit-flipped ciphertext,
  decap returns a pseudorandom shared secret without panicking.

## Secret handling

Every public type that holds secret material carries:

* `#[derive(Zeroize, ZeroizeOnDrop)]` — bytes are wiped on drop.
* Custom `Debug` impl that prints `[REDACTED N bytes]` (verified by
  [`tests/test_snapshots.rs`](../../crates/kyberlib/tests/test_snapshots.rs)).
* `pub` accessor for the bytes (`as_bytes() -> &[u8; N]`) so
  consumers can serialize them deliberately. No accidental leakage
  through default `Debug` / `Display`.

The legacy `Keypair { pub public, pub secret }` is `#[deprecated]` in
favour of the typed `MlKem*DecapKey` / `MlKem*EncapKey` split, which
keeps the secret bytes private behind `as_bytes()`.

## What kyberlib does NOT promise

* **Side-channel resistance against power analysis** — out of scope;
  hardware countermeasure crates (e.g.
  [`zerocopy::FromBytes`](https://docs.rs/zerocopy)) handle that layer.
* **Quantum resistance of the X25519 half of the hybrid construction**
  — when used in `kyberlib-hybrid`, X25519 provides classical
  hardness only. The ML-KEM half is the post-quantum guarantee.
* **FIPS 140-3 module validation** — kyberlib is not currently a
  CMVP-validated module. Issue
  [#170](https://github.com/sebastienrousseau/kyberlib/issues/170)
  tracks a `fips` Cargo feature delegating to `aws-lc-rs`'s
  CMVP-in-process ML-KEM implementation.

## Reporting vulnerabilities

See [`SECURITY.md`](../../SECURITY.md) at the workspace root.
