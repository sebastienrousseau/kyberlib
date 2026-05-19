# kyberlib-hybrid

> **Skeleton.** Hybrid PQ + classical KEMs over `kyberlib`. Not yet usable.

Per [`draft-ietf-tls-ecdhe-mlkem-04`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/):

| Type                  | Codepoint | Classical    | Post-quantum  |
|-----------------------|-----------|--------------|---------------|
| `X25519MlKem768`      | `0x11EC`  | X25519       | ML-KEM-768    |
| `SecP256r1MlKem768`   | `0x11EB`  | NIST P-256   | ML-KEM-768    |
| `SecP384r1MlKem1024`  | `0x11ED`  | NIST P-384   | ML-KEM-1024   |

The shared secret is the concatenation of the two component secrets,
fed into the consumer's KDF (TLS 1.3's HKDF for hybrid TLS).

## Status

`publish = false`. Hold until [#147](https://github.com/sebastienrousseau/kyberlib/issues/147)
(Phase 2(b) FIPS 203 patch) lands. See `src/lib.rs` for the rationale
and [#167](https://github.com/sebastienrousseau/kyberlib/issues/167)
for the design discussion.

## Why this skeleton ships now

So the workspace member list and trait surface are in place. Future
phase work can flesh out the implementation without touching the
public-facing crate layout.
