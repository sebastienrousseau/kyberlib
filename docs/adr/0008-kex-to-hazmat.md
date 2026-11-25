# ADR 0008 — Move `Uake` / `Ake` under `hazmat::kex`

* **Status:** Accepted (v0.0.15)
* **Date of decision:** 2026-11-07
* **Authors:** sebastienrousseau
* **Tracking issue:** [#156](https://github.com/sebastienrousseau/kyberlib/issues/156)

## Context

kyberlib inherited two key exchanges from the CRYSTALS-Kyber reference
code (`kex.c`): `Uake` (client encapsulates to the server's long-term key
and to its own ephemeral key) and `Ake` (as `Uake`, plus an encapsulation
to the client's long-term key). Until v0.0.14 they sat at the crate root
next to the FIPS 203 API, as `kyberlib::Uake` and `kyberlib::Ake`.

Their names promise authenticated key exchange, but the authentication is
implicit only: a party without the expected long-term decapsulation key
derives a different secret and nobody is told. There is no key
confirmation, no identity or transcript binding, no replay protection,
and neither protocol is specified by FIPS 203 or any RFC. Issue #156 asked
to either move them into `hazmat` with a warning, or into a separate crate.

## Decision

Move them to `kyberlib::hazmat::kex`, behind the existing `hazmat`
feature, with a module-level threat model. The handshake constants and
message types (`UAKE_INIT_BYTES`, `UakeSendInit`, ...) and the six
`kyberlib_uake_*` / `kyberlib_ake_*` macros move with them. The legacy
type aliases the free-function API uses (`PublicKey`, `SecretKey`,
`SharedSecret`, `Encapsulated`, `Decapsulated`) stay public at the crate
root, now defined in `api.rs`.

A separate `kyberlib-experimental` crate was rejected: it would add a
crate to publish, vet and version for two types, while `hazmat` already
exists for exactly this purpose (it also gates the IND-CPA primitives).

Both types also gained `#[non_exhaustive]` (#157).

## Consequences

* Breaking: code using `kyberlib::Uake`, `kyberlib::Ake` or the moved
  constants and macros must enable `hazmat` and import from
  `kyberlib::hazmat::kex`. Struct literals and struct-update syntax no
  longer compile; use `new()` / `default()`.
* The default build no longer exposes a protocol that looks safer than it
  is.
* kyberlib-wasm is unaffected: its `Kex` type wraps the plain KEM.
