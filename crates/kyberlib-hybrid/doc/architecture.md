# Architecture

> Last Updated: 2026-05-22

`kyberlib-hybrid` provides the IETF TLS WG's hybrid
post-quantum + classical KEM constructions on top of
`kyberlib` and (for the classical halves) `x25519-dalek`,
`p256` and `p384`. It is the construction TLS 1.3 ships
under [`draft-ietf-tls-ecdhe-mlkem-04`][draft], settled in
Feb 2026 as the migration path away from pure ECDHE.

For the per-item API reference see
[docs.rs/kyberlib-hybrid](https://docs.rs/kyberlib-hybrid)
and the inline `///` rustdoc on `src/lib.rs`. For *using*
the crate see [`guide.md`](./guide.md); for the wire format
see [`spec.md`](./spec.md).

## What "hybrid" means here

The combined KEM concatenates the PQ shared secret with
the classical shared secret:

```text
hybrid_ss := ML-KEM-768.ss  ‖  X25519.ss
          := 32 B            ‖  32 B
          := 64 B total
```

The consumer feeds this 64-byte string into TLS 1.3's HKDF
extractor — TLS treats it like any other ECDHE-derived
shared secret. The construction is secure as long as
*either* the ML-KEM or the X25519 half is secure: a
"defence in depth" against future cryptanalytic breaks of
*either* primitive.

## Why each codepoint exists

| Codepoint | Construction | Why |
|---|---|---|
| `0x11EC` | `X25519MlKem768` | The default. X25519 is the fastest classical KEM with no patent / IPR overhead. |
| `0x11EB` | `SecP256r1MlKem768` | NIST P-256 for organisations whose policy mandates a NIST-approved classical half (e.g. CNSA 2.0). |
| `0x11ED` | `SecP384r1MlKem1024` | The CNSA 2.0 top-tier — both halves at NIST cat-5 strength. |

The codepoints are reserved with IANA under the TLS
NamedGroup registry. Other hybrids (Kyber-1024 + X25519,
FrodoKEM + P-256) exist in the IETF draft history but
were not picked up by the WG and are not implemented here.

## Module map

```text
crates/kyberlib-hybrid/src/
├── lib.rs                Sealed `Hybrid` trait + marker types +
│                         per-construction implementation modules.
└── lib.rs::x25519_impl   Phase 5.1 wired today (cfg = x25519).
```

The other two constructions (`SecP256r1MlKem768`,
`SecP384r1MlKem1024`) declare their marker types and trait
impls but the keygen / encap / decap impls are pending —
the ECDH choice is gated on [#167](https://github.com/sebastienrousseau/kyberlib/issues/167).

## Sealed-trait pattern

`Hybrid` is a sealed marker trait — only this crate can
implement it. The sealed pattern uses an inner module:

```rust
pub trait Hybrid: sealed::Sealed { /* ... */ }
mod sealed { pub trait Sealed {} }
```

Downstream consumers can write generic code over `<H:
Hybrid>` but cannot define their own hybrids. This is
deliberate: every hybrid in this crate is paired to an
IANA codepoint and a wire-format spec — letting third
parties add hybrids would be either a footgun (TLS peers
won't interoperate) or a re-introduction of the JWT
"alg=none" failure mode (downgrade to classical-only).

## Secret handling

Every hybrid `*Client` / `*Server` struct that holds
secret material derives `Zeroize + ZeroizeOnDrop` and has
a custom `Debug` impl that prints
`*([REDACTED N bytes])`. The pattern matches the safe-
core `MlKem*DecapKey` types in `kyberlib`.

In the X25519 half this works because
`x25519_dalek::StaticSecret` itself derives
`ZeroizeOnDrop`. The ML-KEM half is covered by
`kyberlib`'s typed `MlKem768DecapKey`.

## Constant-time properties

The X25519 half: relies on `x25519_dalek`'s curve25519
ladder, which is the field's reference CT implementation
(per [Curve25519: new Diffie-Hellman speed records][bern25519]).

The ML-KEM half: inherits the FIPS 203 §6.3 implicit-
rejection construction from `kyberlib` v0.0.7. See
`crates/kyberlib/doc/safety.md` for the CT story.

The *combination* is straight byte concatenation — no
secret-dependent branches and no compression. The full
hybrid is CT-equivalent to the weaker of the two halves
(currently X25519, which is the field's gold-standard
CT primitive).

## Non-goals

* **HMAC-based combiners**. The TLS WG considered
  HKDF-Extract on `ml_kem.ss || x25519.ss` to "mix" the
  secrets before passing to TLS. The WG rejected this in
  favour of simple concatenation: TLS 1.3 already
  HKDF-extracts the combined shared secret, so an
  upfront HKDF would be wasted work. We follow the WG.
* **Hybrid signatures**. Out of scope. See `kyberlib-pkcs8`
  for the X.509 / IETF LAMPS surface.
* **PSK + hybrid**. The TLS 1.3 PSK path is orthogonal —
  the hybrid KEM only matters in the ECDHE arm.

## Where to read next

* [`spec.md`](./spec.md) — explicit wire format for each
  codepoint, byte by byte.
* [`guide.md`](./guide.md) — copy-pasteable how-to,
  including TLS-stack integration.
* [`crates/kyberlib/doc/safety.md`](../../kyberlib/doc/safety.md)
  — ML-KEM safety / CT guarantees.

[draft]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[bern25519]: https://cr.yp.to/ecdh.html
