# Wire-format specification

> Last Updated: 2026-05-22

Byte-accurate description of every wire-format string this
crate emits and consumes. Tracks
[`draft-ietf-tls-ecdhe-mlkem-04`][draft] (Feb 2026).

## X25519MlKem768 — codepoint `0x11EC`

### Client share (sent by client in `key_share` extension)

```text
client_share := ek_mlkem768   ‖  pk_x25519
             := 1184 B         ‖  32 B            = 1216 B
```

* `ek_mlkem768`: the ML-KEM-768 encapsulation key, raw,
  as produced by `MlKem768::generate(...).1.as_bytes()`.
* `pk_x25519`: the X25519 public key,
  `x25519_dalek::PublicKey::from(&sk).as_bytes()`.

### Server share (sent by server in `key_share` extension)

```text
server_share := pk_x25519     ‖  ct_mlkem768
             := 32 B            ‖  1088 B          = 1120 B
```

Note the deliberate order swap — client share leads with
PQ, server share leads with classical. This is per the
draft and reflects which side derived which value first.

### Combined shared secret

```text
hybrid_ss := ss_mlkem768  ‖  ss_x25519
          := 32 B          ‖  32 B               = 64 B
```

Both halves are produced by their respective primitives
*before* concatenation. Neither half is HKDF'd or hashed
before the concat — TLS 1.3 will do its own HKDF-Extract.

## SecP256r1MlKem768 — codepoint `0x11EB` (not yet implemented)

### Client share

```text
client_share := ek_mlkem768   ‖  pk_p256_uncompressed
             := 1184 B         ‖  65 B            = 1249 B
```

* `pk_p256_uncompressed`: the SEC 1 uncompressed point
  encoding, `0x04 || X || Y` (each coordinate 32 B).

### Server share

```text
server_share := pk_p256_uncompressed  ‖  ct_mlkem768
             := 65 B                    ‖  1088 B  = 1153 B
```

### Combined shared secret

```text
hybrid_ss := ss_mlkem768  ‖  ss_p256
          := 32 B          ‖  32 B               = 64 B
```

`ss_p256` is the *X-coordinate only* of the ECDH point,
big-endian, 32 B — matching RFC 8446 §4.2.8.2.

## SecP384r1MlKem1024 — codepoint `0x11ED` (not yet implemented)

### Client share

```text
client_share := ek_mlkem1024  ‖  pk_p384_uncompressed
             := 1568 B         ‖  97 B            = 1665 B
```

### Server share

```text
server_share := pk_p384_uncompressed  ‖  ct_mlkem1024
             := 97 B                    ‖  1568 B  = 1665 B
```

Note: P-384 ciphertext sizes match P-384 public-key sizes,
unlike the smaller two constructions — this is because
ML-KEM-1024 has larger public keys (1568 B) and the wire
overhead is dominated by the PQ half regardless.

### Combined shared secret

```text
hybrid_ss := ss_mlkem1024  ‖  ss_p384
          := 32 B           ‖  48 B              = 80 B
```

`ss_p384` is the X-coordinate of the ECDH point, big-
endian, 48 B per SEC 1.

## What the parser MUST check

Per RFC 8446 §4.2.8, a hybrid KEM that fails parsing is a
fatal protocol error, not a fallback condition. Every
parser MUST:

1. **Fixed-length check.** The share byte string MUST be
   *exactly* the spec-fixed length. Short or long shares
   are protocol errors; do not accept truncated input.
2. **No leading or trailing padding.** The byte string is
   the concatenation only — no length prefixes, no
   delimiters.
3. **PQ public key validation.** For `X25519MlKem768`,
   the ML-KEM-768 EncapKey is the first 1184 bytes; reject
   any string shorter than 1184. For the P-256 and P-384
   variants, the PQ side comes first.
4. **Classical share validation.** X25519 has no point-
   validation (per RFC 7748 every byte string is a valid
   public key, with the cofactor handled by the curve).
   P-256 / P-384 MUST validate that the uncompressed
   point is on the curve and not the point-at-infinity.

This crate's `try_from` / `decapsulate` paths perform
these checks; a successful return means parsing
succeeded.

## Conformance test vectors

`tests/smoke.rs` runs a deterministic round-trip with a
seeded RNG to confirm:

* The combined shared secret is identical on both sides.
* The byte lengths match `sizes::X25519_MLKEM768_*`.
* `<X25519MlKem768 as Hybrid>::TLS_CODEPOINT == 0x11EC`.

The IETF draft tracker publishes additional vectors at
[`draft-ietf-tls-ecdhe-mlkem` test vectors][vectors]; once
those stabilise they will land as `tests/vectors_*.rs`.

[draft]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
[vectors]: https://github.com/post-quantum/hybrid-pq-test-vectors
