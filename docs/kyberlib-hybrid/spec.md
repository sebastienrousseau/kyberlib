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
server_share := ct_mlkem768   ‖  pk_x25519
             := 1088 B         ‖  32 B            = 1120 B
```

Both shares lead with the ML-KEM component. X25519MLKEM768 is
the one group in the draft that puts ML-KEM first ("for
historical reasons", §4.1); the `SecP*` groups put the ECDH
share first. Verified against rustls 0.23 (aws-lc-rs) by
`tests/rustls_interop.rs`.

Both peers MUST reject an all-zero X25519 shared secret
(RFC 8446 §7.4.2), and the server MUST run the FIPS 203 §7.2
modulus check on the client's ML-KEM key.

### Combined shared secret

```text
hybrid_ss := ss_mlkem768  ‖  ss_x25519
          := 32 B          ‖  32 B               = 64 B
```

Both halves are produced by their respective primitives
*before* concatenation. Neither half is HKDF'd or hashed
before the concat — TLS 1.3 will do its own HKDF-Extract.

## SecP256r1MlKem768 — codepoint `0x11EB`

The `SecP*` groups put the ECDH component first everywhere
(draft §4.1–§4.3). Verified against rustls 0.23's
`SECP256R1MLKEM768` by `tests/rustls_interop.rs`.

```text
client_share := pk_p256_uncompressed  ‖  ek_mlkem768
             := 65 B                    ‖  1184 B  = 1249 B
server_share := pk_p256_uncompressed  ‖  ct_mlkem768
             := 65 B                    ‖  1088 B  = 1153 B
hybrid_ss    := ss_p256               ‖  ss_mlkem768
             := 32 B                    ‖  32 B    = 64 B
```

* `pk_p256_uncompressed`: SEC 1 uncompressed point,
  `0x04 ‖ X ‖ Y`. Compressed points, off-curve points and the
  identity are rejected with `InvalidKey`.
* `ss_p256`: the X coordinate of the ECDH point, big-endian
  (RFC 8446 §7.4.2).

## SecP384r1MlKem1024 — codepoint `0x11ED`

```text
client_share := pk_p384_uncompressed  ‖  ek_mlkem1024
             := 97 B                    ‖  1568 B  = 1665 B
server_share := pk_p384_uncompressed  ‖  ct_mlkem1024
             := 97 B                    ‖  1568 B  = 1665 B
hybrid_ss    := ss_p384               ‖  ss_mlkem1024
             := 48 B                    ‖  32 B    = 80 B
```

rustls has no `SecP384r1MLKEM1024` group, so the interop vectors
for it combine rustls's `SECP384R1` and `MLKEM1024` groups in the
layout above: the components are checked against an independent
implementation, the concatenation against the draft text.

## X-Wing — draft-connolly-cfrg-xwing-kem-11

A complete KEM rather than a TLS group: one 32-byte secret,
usable as the KEM in HPKE.

```text
decapsulation key := seed (32 B), expanded with SHAKE256 to
                     d (32) ‖ z (32) ‖ sk_X (32)
encapsulation key := pk_mlkem768 ‖ pk_x25519        = 1216 B
ciphertext        := ct_mlkem768 ‖ ct_x25519        = 1120 B
shared secret     := SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ 5c2e2f2f5e5c)
```

All three draft Appendix C vectors pass (`src/xwing.rs` tests).
