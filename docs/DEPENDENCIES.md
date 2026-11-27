# Dependencies: approvals

A new third-party crate needs the maintainer's approval by name, and
the decision is recorded here. Updating an existing crate is not
adding one, unless the update brings new crates with it.

| Crate | Approved | For | Status |
| :-- | :-- | :-- | :-- |
| `kem` | 2026-11-27 | RustCrypto `Encapsulate` / `Decapsulate` traits (#155) | approved, not yet used |
| `coset` | 2026-11-27 | COSE_Encrypt with ML-KEM in `kyberlib-cose` (#169) | approved, not yet used |
| `libcrux-ml-kem` | 2026-11-27 | the `verified` backend (#171) | approved, not yet used |

## Removed

| Crate | Removed | Why |
| :-- | :-- | :-- |
| `sha3` (and `keccak`, `digest`, `crypto-common`, `block-buffer`, `generic-array`, `version_check`) | 0.0.17 | X-Wing uses kyberlib's own FIPS 202 routines (`kyberlib::hash`); `sha3` 0.12 dropped SHAKE, so updating it would have added a crate |
