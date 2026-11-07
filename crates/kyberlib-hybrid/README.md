# kyberlib-hybrid

> Last Updated: 2026-11-06

Hybrid post-quantum + classical key exchange over `kyberlib`: the three
TLS 1.3 groups from
[`draft-ietf-tls-ecdhe-mlkem-05`](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and the general-purpose X-Wing KEM from
[`draft-connolly-cfrg-xwing-kem-11`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

| Type                  | Kind      | Codepoint | Classical  | Post-quantum | Secret | Feature            |
|-----------------------|-----------|-----------|------------|--------------|--------|--------------------|
| `X25519MlKem768`      | TLS group | `0x11EC`  | X25519     | ML-KEM-768   | 64 B   | `x25519` (default) |
| `SecP256r1MlKem768`   | TLS group | `0x11EB`  | NIST P-256 | ML-KEM-768   | 64 B   | `secp256r1`        |
| `SecP384r1MlKem1024`  | TLS group | `0x11ED`  | NIST P-384 | ML-KEM-1024  | 80 B   | `secp384r1`        |
| `XWing*`              | KEM       | n/a       | X25519     | ML-KEM-768   | 32 B   | `xwing` (default)  |

The TLS groups return the concatenation of both component secrets for
the TLS 1.3 key schedule to absorb. X-Wing hashes them into one 32-byte
secret with SHA3-256, so it can be used directly, for example as the
KEM in HPKE.

## How it is checked

- **Interop:** `tests/rustls_interop.rs` replays handshakes captured
  against rustls 0.23 (aws-lc-rs) in both directions for every TLS
  group. Regenerate with `crates/kyberlib-hybrid/interop-gen`.
- **Known answers:** the three X-Wing vectors from the draft's
  Appendix C, run in `src/xwing.rs`.
- **Mandatory checks:** the FIPS 203 §7.2 key check on the server,
  the all-zero X25519 check, and SEC 1 point validation
  (`tests/input_checks.rs`, `tests/secp_input_checks.rs`).

Wire layouts are in [`doc/spec.md`](doc/spec.md).

## Status

`publish = false` until the third-party audit
([#177](https://github.com/sebastienrousseau/kyberlib/issues/177))
closes. Use it as a git or path dependency until then.
