# ADR 0005 — Bring-Your-Own-Entropy (BYOE) deterministic API

* **Status:** Proposed (planned for v0.0.8, branch `feat/v0.0.8-byoe`)
* **Date:** 2026-05-20
* **Authors:** sebastienrousseau
* **Tracking issue:** TBD on v0.0.8 kickoff

## Context

The v0.0.7 surface accepts an RNG at the call site:

```rust
let (dk, ek) = MlKem768::generate(&mut rng)?;
let (ct, ss) = ek.encapsulate(&mut rng)?;
```

This works, but couples three concerns into a single function:

1. **Entropy acquisition** — the caller (or `rand::thread_rng()`)
   pulls 64 bytes for keygen and 32 bytes for encaps.
2. **Domain separation + spec arithmetic** — the FIPS 203 `(d, z)` /
   `m` derivation per §5.1 and §6.2.
3. **Result construction** — typed wrappers, zeroization, etc.

Four downstream problems follow from this coupling:

* **ACVP harness drag.** NIST's ACVP vectors provide `d`, `z`, and
  `m` directly. With our current API we have to wrap them in a
  custom `AcvpMockRng: CryptoRng + RngCore` shim that hands those
  exact bytes back. That shim is in
  [`crates/kyberlib/tests/acvp_rng.rs`](../../crates/kyberlib/tests/test_acvp.rs)
  and adds ~80 LoC plus a `cfg(KYBER_SECURITY_PARAMETERat)` gate.
* **`no_std` friction.** Embedded callers need `rand_core::OsRng`
  or a hardware-RNG wrapper that implements both `CryptoRng` and
  `RngCore`. Most do — but the dependency closure is non-trivial
  on bare metal.
* **FIPS 140-3 boundary violation.** CMVP rules forbid injecting
  external entropy into a validated module for production keygen.
  When the planned `fips` feature (ADR 0006) goes live and routes
  through `aws-lc-rs`, the user-supplied `&mut rng` parameter is
  silently *ignored* — which is a footgun if the documentation
  doesn't shout about it.
* **Library-level `rand` dependency.** `rand` pulls a non-trivial
  transitive surface (`rand_chacha`, `ppv-lite86`, `getrandom`).
  Some downstream consumers want kyberlib in a `cargo-vet`-vetted
  graph that excludes `rand`.

## Decision

We will pivot the primary KEM surface to **deterministic entry
points** that take entropy as `[u8; 32]` / `[u8; 64]` arguments
directly, with an *optional* convenience wrapper gated by a new
`getrandom` Cargo feature.

### Trait surface

```rust
pub trait KemCore: Sized {
    type EncapKey;
    type DecapKey;

    /// FIPS 203 §5.1 KeyGen. Deterministic in (d, z).
    /// Caller is responsible for sourcing 64 cryptographically
    /// secure bytes; trusted-boundary RNG decisions live entirely
    /// at the call site.
    fn generate_deterministic(
        d: [u8; 32],
        z: [u8; 32],
    ) -> Result<(Self::DecapKey, Self::EncapKey), KyberLibError>;

    /// FIPS 203 §6.2 Encaps. Deterministic in `m`. Caller is
    /// responsible for sourcing 32 cryptographically secure bytes.
    fn encapsulate_deterministic(
        ek: &Self::EncapKey,
        m: [u8; 32],
    ) -> Result<(Ciphertext, SharedSecret), KyberLibError>;

    /// Decaps is mathematically deterministic — unchanged from v0.0.7.
    fn decapsulate(
        dk: &Self::DecapKey,
        ct: &Ciphertext,
    ) -> SharedSecret;
}
```

### Convenience wrappers (gated)

```rust
#[cfg(any(feature = "getrandom", feature = "fips"))]
impl MlKem768 {
    /// Default-RNG keygen. Routes via:
    /// - `getrandom` feature → host OS CSPRNG (`getrandom::getrandom`)
    /// - `fips` feature      → AWS-LC internal approved DRBG
    pub fn generate() -> Result<(Self::DecapKey, Self::EncapKey), KyberLibError> {
        #[cfg(feature = "fips")]
        { /* delegate to aws_lc_rs::kem::DecapsulationKey::generate */ }

        #[cfg(all(feature = "getrandom", not(feature = "fips")))]
        {
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            getrandom::getrandom(&mut d).map_err(|_| KyberLibError::RngFailure)?;
            getrandom::getrandom(&mut z).map_err(|_| KyberLibError::RngFailure)?;
            Self::generate_deterministic(d, z)
        }
    }
}
```

### Dependency graph

| Crate | Change |
|---|---|
| `kyberlib` core | `rand` drops from required deps. `getrandom` becomes an optional dep, gated by feature. `rand_core` retained only for trait re-exports if any consumer still needs them. |
| `kyberlib-hybrid` | The X25519 half still needs `x25519-dalek`'s RNG signature. Internal: pull 32 bytes via `getrandom` (under that feature) and pass to `StaticSecret::from(bytes)`. Hybrid keeps its current `&mut rng` parameter under the `x25519-rng` feature; deterministic variant added. |
| `kyberlib-wasm` | The WASM binding's `keypair()` JS function continues to call `OsRng` internally — JS callers don't get a deterministic entry point. |
| Tests | Every `MlKem768::generate(&mut rng)` site flips to either `MlKem768::generate()` (feature-gated convenience) or `MlKem768::generate_deterministic(d, z)`. |

## Consequences

### Positive

* **ACVP harness drops ~80 LoC.** The `AcvpMockRng` shim deletes
  entirely; vectors map 1:1 onto `generate_deterministic(d, z)`.
* **`no_std` story improves.** No required `rand` dependency; the
  base library is zero-deps (modulo `zeroize`).
* **FIPS facade lands cleanly (ADR 0006).** The deterministic
  entry points `fail-closed` under `--features fips` with a clear
  `KyberLibError::FipsBoundaryError`. The convenience `generate()`
  wrapper transparently routes to the AWS-LC internal DRBG.
* **`getrandom` is opt-in.** Embedded users who can't depend on
  `getrandom` can skip the feature and use `generate_deterministic`
  with their own TRNG.

### Negative

* **BREAKING for every existing caller.** The current
  `MlKem768::generate(rng)` surface goes away (or becomes a
  feature-gated convenience that compiles only with
  `default-features = ["getrandom"]`). Every doctest, example, and
  downstream test rewires.
* **Default-feature ergonomics depend on `getrandom`.** New users
  who `cargo add kyberlib` and copy-paste a quick-start expect
  `MlKem768::generate()` to "just work". That means we need
  `getrandom` in the default-features list to preserve the v0.0.7
  ergonomics — at the cost of one transitive dep on hosted targets.
* **Footgun for the unwary.** A caller who passes
  `[0u8; 32]` as `d` and `z` generates a deterministic, world-
  knowable keypair. The rustdoc must shout about this.

### Migration

```diff
-let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (dk, ek) = MlKem768::generate()?;  // default-features = ["getrandom"]
```

OR for the explicit-entropy path:

```diff
-let (dk, ek) = MlKem768::generate(&mut rng)?;
+let mut d = [0u8; 32]; let mut z = [0u8; 32];
+rng.fill_bytes(&mut d); rng.fill_bytes(&mut z);
+let (dk, ek) = MlKem768::generate_deterministic(d, z)?;
```

The legacy free-function API (`kyberlib::keypair(&mut rng)`) is
retained for one further version under
`#[deprecated(since = "0.0.8")]` to give downstream consumers a
compile-time migration warning rather than an immediate API
removal.

## Alternatives considered

### Keep `&mut rng` and add `*_deterministic` siblings

Add `generate_deterministic(d, z)` alongside the existing
`generate(rng)`. Non-breaking, but leaves the FIPS boundary problem
unsolved (the `&mut rng` arg still has to be silently ignored
under `--features fips`) and doesn't shrink the dep graph.

**Rejected** because the long-term goal is a clean FIPS facade
(ADR 0006), and the silent-ignore footgun is worse than the
explicit migration cost.

### Sealed `ApprovedRng` trait

Restrict the RNG parameter to a sealed trait that only the
crate's own wrappers implement, so FIPS mode can statically
guarantee an approved DRBG. Elegant but extremely intrusive —
every existing caller of `MlKem768::generate(&mut rng)` would
need to switch to `Approved::new(rng)` first.

**Rejected** because the BYOE approach achieves the same FIPS
guarantee with a smaller API.

## Implementation phases

* **Phase 1** — land deterministic trait methods alongside the
  existing RNG-taking ones. Both compile; existing tests continue
  to pass.
* **Phase 2** — wire the ACVP harness onto the deterministic
  methods; delete `AcvpMockRng`.
* **Phase 3** — deprecate `MlKem768::generate(rng)` (compile-time
  warning) and update all docs / examples / cookbook recipes.
* **Phase 4** — remove the RNG-taking signatures in v0.0.9 (after
  one minor cycle on `#[deprecated]`).

## References

* [FIPS 203 §5.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — KeyGen requires explicit `d`, `z`
* [FIPS 203 §6.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — Encaps requires explicit `m`
* [`rust-lang/api-guidelines#api-c-stable`](https://rust-lang.github.io/api-guidelines/dependability.html#c-stable) — the case for shrinking transitive dep graphs
* [ADR 0006](./0006-fips-facade.md) — FIPS facade (consumer of this ADR)
