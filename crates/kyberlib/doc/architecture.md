# Architecture

How the `kyberlib` crate is laid out, the mental model required to
understand it, and why each module exists. Targeted at advanced users
and new contributors. For *using* the library, see
[`GETTING_STARTED.md`](../../../GETTING_STARTED.md); for the per-item
API reference see [docs.rs/kyberlib](https://docs.rs/kyberlib).

## Module map

```text
crates/kyberlib/src/
├── lib.rs              crate root + re-exports + lint policy
├── api.rs              legacy free-function surface (keypair / encapsulate / decapsulate)
├── error.rs            `KyberLibError` enum (non_exhaustive)
├── kem.rs              FO transform on top of indcpa (the kem_*_generic pipeline)
├── kex.rs              `Uake` / `Ake` authenticated key-exchange wrappers
├── macros.rs           kyberlib_* convenience macros (legacy surface)
├── ml_kem.rs           v0.0.7 typed-state API (KemCore trait + MlKem512/768/1024)
├── oid.rs              IETF LAMPS object identifiers
├── params.rs           parameter constants (cfg-gated, legacy)
├── paramsets.rs        MlKemParams trait — unified parameter pack (#130b)
├── rng.rs              `randombytes` wrapper around rand_core::RngCore
├── symmetric.rs        SHAKE / AES-256-CTR backend selection
├── avx2/               (cfg-gated) AVX2-accelerated backend
└── reference/          pure-Rust reference backend (the audit target)
    ├── mod.rs
    ├── aes256ctr.rs    "90s mode" symmetric primitive (deprecated)
    ├── cbd.rs          centred-binomial sampler (η = 2 / 3)
    ├── fips202.rs      SHAKE / SHA-3 implementation
    ├── indcpa.rs       IND-CPA layer (gen_matrix + keypair/enc/dec)
    ├── ntt.rs          number-theoretic transform
    ├── poly.rs         polynomial operations over Z_q[X]/(X^256+1)
    ├── polyvec.rs      vector-of-polynomials operations
    ├── reduce.rs       Barrett + Montgomery modular reduction
    └── verify.rs       constant-time comparison + cmov
```

## The two APIs

kyberlib's public surface presents the same algorithm via two distinct
shapes:

### Legacy free-function API (`crate::api`)

```rust
use kyberlib::{keypair, encapsulate, decapsulate};

let bob = keypair(&mut rng)?;
let (ct, ss_a) = encapsulate(&bob.public, &mut rng)?;
let ss_b = decapsulate(&ct, &bob.secret)?;
```

* Bytes flow as `&[u8]` / `[u8; KYBER_*_BYTES]`.
* Parameter set is fixed at build time via the `kyber512` /
  `kyber768` (default) / `kyber1024` Cargo features.
* Retained for downstream-consumer migration from v0.0.6.
* `#[deprecated]` annotations land in v0.1.

### v0.0.7 typed-state API (`crate::ml_kem`)

```rust
use kyberlib::{KemCore, MlKem768};

let (dk, ek) = MlKem768::generate(&mut rng)?;
let (ct, ss_a) = ek.encapsulate(&mut rng)?;
let ss_b = dk.decapsulate(&ct);
```

* Each marker type ([`MlKem512`], [`MlKem768`], [`MlKem1024`])
  implements [`KemCore`].
* Secrets ride in distinct types ([`MlKem768DecapKey`] vs
  [`MlKem768EncapKey`]) with redacted `Debug` and `ZeroizeOnDrop`.
* All three parameter sets coexist in any single build (post-#130b).

## The const-generic pipeline (#130b)

The internal algorithm pipeline is generic over the `MlKemParams`
trait (see [`crate::paramsets`]). Every primitive — `polyvec_compress`,
`indcpa_keypair`, `kem_dec`, etc. — has a `_generic<P: MlKemParams>`
variant that drives per-set numeric parameters off the trait's
associated consts (`P::K`, `P::ETA1`, `P::DU`, `P::DV`).

The associated *types* (`P::PublicKeyBytes`, `P::SecretKeyBytes`,
`P::CiphertextBytes`) are each `[u8; N]` for the appropriate `N`,
sidestepping the stable-Rust restriction that prevents
`[u8; K * P::POLY_BYTES]` in generic contexts.

Internal workspaces (matrix `[Poly; K*K]`, polyvecs `[Poly; K]`)
use a `MAX_K = 4` fixed-size stack-allocated array with only the
first `P::K` slots used. Stack overhead is ~14 KB per top-level
call — acceptable for non-embedded targets.

See [`paramsets.rs`](../src/paramsets.rs) for the trait itself
and the unit tests verifying FIPS 203 §6 formulas.

## Two backends — which one is active?

```text
       ┌─────────────────────────────────────────────────────────┐
       │  Cargo features                                         │
       │                                                         │
       │   default = ["kyber768", "std"]                         │
       │                                                         │
       │   #[cfg(all(target_arch = "x86_64", feature = "avx2"))] │
       │       mod avx2;       ← uses unsafe SIMD intrinsics     │
       │   #[cfg(not(...))]                                      │
       │       mod reference;  ← pure-safe-Rust port             │
       │                                                         │
       └─────────────────────────────────────────────────────────┘
```

* `reference/` is the audit target. KyberSlash audit (ADR 0003) was
  performed against this backend; FIPS 203 ACVP conformance is verified
  against this backend (180 / 180 vectors green).
* `avx2/` is performance-only. Lifting it into a dedicated crate is
  tracked as #143 (see [ADR 0002](../../../doc/adr/0002-asm-quarantine.md)).

## Safety boundaries

* **`#![forbid(unsafe_code)]`** on the safe core under default features.
  This is the strongest Rust lint level — inner `#[allow]` cannot lift it.
* **`#![deny(unsafe_code)]` + `#[cfg_attr(avx2, allow(unsafe_code))]`
  on `mod avx2;`** under `--features avx2`. Granular gate — the
  safe-core modules stay unsafe-free even when SIMD is enabled.
* Every `unsafe` block in `avx2/` is paired with a `// SAFETY:` comment
  describing the invariant the call relies on.

See [`safety.md`](./safety.md) for the full unsafe policy + the
constant-time guarantees.

## Where to read next

* [`safety.md`](./safety.md) — unsafe policy, CT guarantees, panic-freedom
* [`migration-from-0.0.6.md`](./migration-from-0.0.6.md) — explicit
  before/after for the v0.0.6 → v0.0.7 breaking changes
* [`cookbook.md`](./cookbook.md) — copy-pasteable recipes for common
  integrations (TLS hybrid, file-at-rest encryption, KEM-only
  application protocols)
* [`release-process.md`](./release-process.md) — for maintainers:
  tagging, SLSA L3 attestation, cosign keyless signing
* [`../../../doc/adr/`](../../../doc/adr/) — workspace-wide ADRs

[`MlKem512`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem512.html
[`MlKem768`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768.html
[`MlKem1024`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem1024.html
[`MlKem768EncapKey`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768EncapKey.html
[`MlKem768DecapKey`]: https://docs.rs/kyberlib/latest/kyberlib/struct.MlKem768DecapKey.html
[`KemCore`]: https://docs.rs/kyberlib/latest/kyberlib/trait.KemCore.html
[`crate::paramsets`]: https://docs.rs/kyberlib/latest/kyberlib/paramsets/index.html
