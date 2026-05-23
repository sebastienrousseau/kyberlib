# Guide

> Last Updated: 2026-05-22

Practical how-to for integrating `kyberlib-hybrid` into a
TLS stack or a bespoke handshake protocol. For the
byte-level wire format see [`spec.md`](./spec.md); for the
design rationale see [`architecture.md`](./architecture.md).

## When to use this crate

Use `kyberlib-hybrid` when you need:

* TLS 1.3 hybrid key exchange per [`draft-ietf-tls-ecdhe-mlkem-04`][draft]
  (the construction that ships in OpenSSL 3.5+, Rustls
  0.23+, BoringSSL post-Q4 2025);
* Or a bespoke protocol whose threat model wants "either
  ML-KEM is secure *or* X25519 is secure".

Use the bare `kyberlib` crate when you need:

* ML-KEM-only key exchange (e.g. CNSA 2.0 high-assurance
  mode);
* Lower wire overhead — the hybrid adds ~16% to client
  shares.

## Setup

```toml
[dependencies]
kyberlib-hybrid = { version = "0.0.7", features = ["x25519"] }
```

The `x25519` feature is required to compile the
`X25519MlKem768` construction. It is *on by default* in
v0.0.7 but stays feature-gated so a `no_std` consumer who
wants only the `Hybrid` trait surface can pick
`--no-default-features`.

## Round-trip example

```rust
use kyberlib_hybrid::X25519MlKem768Client;
use kyberlib_hybrid::X25519MlKem768Server;
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Client: generate ephemeral keys, emit client_share.
    let (client_state, client_share) = X25519MlKem768Client::generate(&mut rng)?;

    // Wire: client_share goes over the network as 1216 bytes.

    // Server: receive client_share, derive shared_secret + server_share.
    let (shared_secret_server, server_share) =
        X25519MlKem768Server::respond(&client_share, &mut rng)?;

    // Wire: server_share goes back as 1120 bytes.

    // Client: receive server_share, derive shared_secret.
    let shared_secret_client = client_state.decapsulate(&server_share)?;

    // Both sides now share the same 64-byte string.
    assert_eq!(shared_secret_server, shared_secret_client);
    assert_eq!(shared_secret_server.len(), 64);

    Ok(())
}
```

## TLS 1.3 integration

For a Rustls-style TLS stack, plug the hybrid in at the
NamedGroup level:

```rust,ignore
// Pseudocode — actual Rustls API may differ.
use kyberlib_hybrid::{X25519MlKem768, Hybrid};

const NAMED_GROUP_X25519_MLKEM768: u16 =
    <X25519MlKem768 as Hybrid>::TLS_CODEPOINT;

// In the ClientHello extensions:
named_groups.push(NAMED_GROUP_X25519_MLKEM768);

// In key_share:
key_share.push(KeyShareEntry {
    group: NAMED_GROUP_X25519_MLKEM768,
    key_exchange: client_share.to_vec(),
});
```

The 64-byte combined shared secret feeds straight into
TLS 1.3's HKDF-Extract as the `IKM`. TLS 1.3 will handle
the transcript binding.

## Performance characteristics

On an Apple M2 (single core, release build, criterion
1000-sample mean):

| Operation | X25519 alone | ML-KEM-768 alone | X25519MlKem768 |
|---|---|---|---|
| Keygen + serialise client | ~30 µs | ~16 µs | ~46 µs |
| Server respond (1 round-trip) | ~30 µs | ~21 µs | ~51 µs |
| Client decap | ~30 µs | ~22 µs | ~52 µs |

The hybrid is roughly the sum of the two halves — the
concatenation step is free. Wire overhead:

| Direction | Bytes |
|---|---|
| Client share (`0x11EC`) | 1216 |
| Server share (`0x11EC`) | 1120 |
| Pure ECDHE X25519 client share | 32 |

The 1.2 KB blow-up on the client side is *the* deployment
cost of hybrid TLS. For most use cases this is dwarfed by
the certificate chain (typically 3–5 KB), but it does
affect QUIC connection-establishment cost.

## Choosing a construction

```
┌─────────────────────────────────────────────────────┐
│ Use X25519MlKem768  if:                             │
│   • You're not bound by a NIST-curve policy         │
│   • You want the IETF default (Rustls / OpenSSL /   │
│     BoringSSL ship this as the priority codepoint)  │
│                                                     │
│ Use SecP256r1MlKem768  if:                          │
│   • Your policy mandates NIST-approved curves       │
│     (FIPS 140-3 contexts; some US-gov procurement)  │
│   • You want backwards compat with hardware HSMs    │
│     that don't speak X25519                         │
│                                                     │
│ Use SecP384r1MlKem1024  if:                         │
│   • CNSA 2.0 — top tier, both halves cat-5          │
│   • Or your threat model assumes large quantum      │
│     adversaries (>2^60 logical-qubit budget)        │
└─────────────────────────────────────────────────────┘
```

## Common pitfalls

1. **Mixing the byte order.** Client-share is
   `ek_mlkem ‖ pk_x25519`; server-share is `pk_x25519 ‖
   ct_mlkem`. The order swap is per the draft; don't
   reverse it.
2. **Truncating the shared secret.** The combined shared
   secret is 64 bytes for the `*MlKem768` variants. Don't
   truncate to 32 — TLS expects the full IKM.
3. **Validation skipped on the classical side.** P-256
   and P-384 public keys MUST be validated on-curve;
   X25519 doesn't need point-validation (per RFC 7748).
4. **State reuse.** `X25519MlKem768Client::generate`
   returns a single-use state. Reusing it across
   handshakes leaks the ephemeral secret and breaks
   forward secrecy. Generate a fresh state per
   connection.

## See also

* [`spec.md`](./spec.md) — wire format byte by byte.
* [`architecture.md`](./architecture.md) — sealed-trait
  rationale.
* [`examples/x25519_mlkem768_round_trip.rs`](../examples/x25519_mlkem768_round_trip.rs)
  — full runnable example.

[draft]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
