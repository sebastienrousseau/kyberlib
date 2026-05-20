# Migration from kyberlib 0.0.6

Explicit before/after walkthrough of the breaking and notable
behavioural changes in v0.0.7. For the *new* features (the typed-
state API, multi-parameter-set support in one build), see
[`architecture.md`](./architecture.md) and the workspace
[`GETTING_STARTED.md`](../../../GETTING_STARTED.md).

## TL;DR

The legacy free-function surface (`keypair`, `encapsulate`,
`decapsulate`) still works without changes for ML-KEM-768 consumers.
Most v0.0.6 → v0.0.7 migrations need no code edits — only a Cargo.toml
bump.

The breaking changes only affect consumers who:

1. Used the removed `wasm` or `zeroize` Cargo features (now no-ops
   and removed).
2. Pattern-matched on `KyberLibError` variants directly without a
   wildcard arm (now `#[non_exhaustive]`).
3. Used the `pub fn public(sk)` extractor that previously panicked
   on short input.

Everything else is purely additive.

## FIPS 203 spec migration

kyberlib v0.0.6 implemented CRYSTALS-Kyber Round 3 (the pre-
standardisation form). v0.0.7 implements the final FIPS 203
standard, which differs in three places:

| Step | Round 3 (v0.0.6) | FIPS 203 (v0.0.7) |
|---|---|---|
| Keygen | `G(d)` → publicseed‖noiseseed | `G(d ‖ K)` where `K` is the module rank byte (2/3/4) |
| Encap pre-hash | `m' = H(m)` then encrypt `m'` | Encrypt `m` directly (no pre-hash) |
| Decap KDF | `KDF(K̄ ‖ H(c))` | `K` directly is the first half of `G`'s output (no post-KDF) |
| Rejection input | `KDF(z ‖ H(c))` | `J(z ‖ c) = SHAKE256(z ‖ c, 32)` |

**Consequence**: ciphertexts and shared secrets produced by v0.0.6
will NOT round-trip with v0.0.7. If you need wire compatibility with
v0.0.6 peers, pin to v0.0.6; otherwise migrate both ends in lockstep.

## Removed Cargo features

### `wasm`

```toml
# v0.0.6
kyberlib = { version = "0.0.6", features = ["wasm"] }

# v0.0.7 — use the dedicated crate instead
kyberlib-wasm = "0.0.7"
```

The `wasm` feature on the core crate was a no-op since v0.0.6 —
the wasm-bindgen surface always lived in `kyberlib-wasm/`. v0.0.7
removes the compat shim.

### `zeroize`

```toml
# v0.0.6
kyberlib = { version = "0.0.6", features = ["zeroize"] }

# v0.0.7
kyberlib = "0.0.7"
```

`Zeroize` / `ZeroizeOnDrop` are now derived unconditionally on every
secret-bearing type. The feature was a no-op opt-out.

## API changes

### `KyberLibError` is now `#[non_exhaustive]`

```rust
// v0.0.6 — exhaustive match was allowed
match err {
    KyberLibError::InvalidInput => ...,
    KyberLibError::Decapsulation => ...,
    KyberLibError::RandomBytesGeneration => ...,
}

// v0.0.7 — wildcard required
match err {
    KyberLibError::InvalidInput => ...,
    KyberLibError::Decapsulation => ...,
    KyberLibError::RandomBytesGeneration => ...,
    KyberLibError::InvalidKey => ...,        // new variant
    KyberLibError::InvalidLength => ...,     // new variant
    _ => ...,                                 // wildcard for future variants
}
```

### `Keypair` is soft-deprecated

```rust
// v0.0.6 — still works in v0.0.7
let keys = keypair(&mut rng)?;
let pub_bytes: &[u8] = &keys.public;
let sec_bytes: &[u8] = &keys.secret;

// v0.0.7 — typed split with redacted Debug + ZeroizeOnDrop
use kyberlib::{KemCore, MlKem768};
let (dk, ek) = MlKem768::generate(&mut rng)?;
let pub_bytes: &[u8] = ek.as_bytes();
let sec_bytes: &[u8] = dk.as_bytes();  // mind the secret surface
```

The free `keypair()` function still exists — it now delegates
internally to `MlKem768::generate`. The `Keypair` struct will move
to `#[deprecated]` in v0.1.

### Constants renamed

```rust
// v0.0.6
const PK_LEN: usize = kyberlib::KYBER_PUBLIC_KEY_BYTES;

// v0.0.7 — preferred (parameter-set explicit)
use kyberlib::{MlKem768, MlKemParams};
const PK_LEN: usize = <MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES;

// v0.0.7 — legacy aliases still work
const PK_LEN: usize = kyberlib::KYBER_PUBLIC_KEY_BYTES;  // = 1184
```

The `KYBER_*` aliases route to the active build's parameter set
(default `kyber768`). The canonical names are now the trait-
associated consts on the marker types.

## Behavioural changes

### Multi-parameter-set support

```rust
// v0.0.6 — one parameter set per build via Cargo features
// (default kyber768; kyber512 and kyber1024 commented out)

// v0.0.7 — all three coexist in any single build
use kyberlib::{KemCore, MlKem512, MlKem768, MlKem1024};
let (_, ek_512)  = MlKem512::generate(&mut rng)?;
let (_, ek_768)  = MlKem768::generate(&mut rng)?;
let (_, ek_1024) = MlKem1024::generate(&mut rng)?;
// pk sizes 800 / 1184 / 1568 bytes; all three work simultaneously.
```

The const-generic refactor (#130b) lifted the cfg-gated parameter
selection up to the type system. Existing code pinning to a single
parameter via Cargo features keeps working; new code can write
generic `fn foo<P: KemCore>(...)`.

### Implicit-rejection invariant

```rust
// v0.0.6 — decap could return Err(Decapsulation) on tampered CT
let ss = decapsulate(&tampered_ct, &sk).unwrap();  // panics

// v0.0.7 — FIPS 203 §6.3 implicit rejection: returns a pseudorandom SS
let ss = decapsulate(&tampered_ct, &sk).expect("never errors on length-valid ct");
// ss is now a deterministic pseudorandom value, NOT the original secret.
```

`KyberLibError::Decapsulation` is retained in the enum (since it's
`#[non_exhaustive]`) but is no longer returned by the public
`decapsulate`. The current cause-of-error variants are `InvalidInput`
and `RandomBytesGeneration`.

## Build-time changes

### MSRV bumped from 1.65 → 1.74

* `[workspace.lints]` (stable in 1.74) — workspace-level lint policy.
* `let ... else` (1.65) — already used in v0.0.6 reference backend.

### `Cargo.lock` checked in

`Cargo.lock` is now committed. Downstream `cargo install kyberlib`
still resolves freshly, but the lockfile pins kyberlib's CI to a
reproducible graph. v0.0.6 deliberately omitted it; v0.0.7
includes it because `kyberlib-wasm` ships a `cdylib` and the lock
file is part of the published artefact surface.

### Tarball trimmed −84%

`cargo package -p kyberlib` size:

| Version | Uncompressed | Compressed |
|---|---|---|
| 0.0.6 | ~1.9 MiB | ~813 KiB |
| 0.0.7 | 475 KiB | 105 KiB |

The reduction comes from tightening the per-crate `include = [...]`
glob to ship test *code* but not the 1.3 MiB of ACVP / KAT fixture
JSON. See `Cargo.toml`'s `[package].include` for the current set.

## Code-level migration checklist

Before bumping the dependency:

- [ ] Audit `match KyberLibError` sites — add wildcard arms.
- [ ] Replace `features = ["wasm"]` with `kyberlib-wasm = "0.0.7"`.
- [ ] Remove `features = ["zeroize"]` (no-op).
- [ ] If you called `kyberlib::public(sk)` — switch to the (soon)
      `extract_public_key(sk)` rename or use the typed API.
- [ ] If you rely on Round-3-form ciphertexts — pin to 0.0.6 OR
      migrate both ends to 0.0.7 simultaneously.

After bumping:

- [ ] Run your test suite. The free-function API is wire-compatible
      with the typed API at the byte level (validated by the
      `kem_keypair_generic_matches_existing_kyber768` test in the
      repo).
- [ ] Consider migrating to the typed API site-by-site as ergonomics
      improvements (redacted `Debug`, type-level parameter set,
      Zeroize-on-drop) become useful.

## Need help

Open an issue tagged `migration`: <https://github.com/sebastienrousseau/kyberlib/issues>.
