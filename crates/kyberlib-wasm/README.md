<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

<p align="center">
  <img src="https://cloudcdn.pro/kyberlib/v1/logos/kyberlib.svg" alt="kyberlib-wasm logo" width="128" />
</p>

<h1 align="center">kyberlib-wasm</h1>

<p align="center"><em>Last Updated: 2026-05-22</em></p>

<p align="center">
  WebAssembly bindings for <a href="https://crates.io/crates/kyberlib"><code>kyberlib</code></a>
  — FIPS 203 ML-KEM (post-quantum key encapsulation) running in
  browsers, Node, Deno, Bun, and Cloudflare Workers via
  <code>wasm-bindgen</code>. ~120 KiB compressed; zero runtime
  dependencies on the JS side.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/kyberlib/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/kyberlib/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/kyberlib-wasm"><img src="https://img.shields.io/crates/v/kyberlib-wasm.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/kyberlib-wasm"><img src="https://img.shields.io/badge/docs.rs-kyberlib--wasm-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://lib.rs/crates/kyberlib-wasm"><img src="https://img.shields.io/badge/lib.rs-kyberlib--wasm-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
  <a href="https://codecov.io/gh/sebastienrousseau/kyberlib"><img src="https://img.shields.io/codecov/c/github/sebastienrousseau/kyberlib?style=for-the-badge&logo=codecov" alt="Coverage" /></a>
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=for-the-badge" alt="License" /></a>
  <a href="https://github.com/sebastienrousseau/kyberlib/blob/main/doc/adr/0001-fips203-migration.md"><img src="https://img.shields.io/badge/FIPS_203-ML--KEM_ACVP_180%2F180-success?style=for-the-badge" alt="FIPS 203 conformance" /></a>
</p>

---

## Contents

**Getting started**

- [Install](#install) — wasm-pack, crates.io
- [Quick Start](#quick-start) — JS round-trip in ten lines

- [The kyberlib ecosystem](#the-kyberlib-ecosystem) — where `kyberlib-wasm` sits in the stack

**JS reference**

- [Migrating to `kyberlib-wasm`](#migrating-to-kyberlib-wasm) — `diff`-style snippets from `@noble/post-quantum`, `@cloudflare/pq`, and pre-FIPS-203 Kyber libs
- [Why this approach?](#why-this-approach) — design rationale
- [Capabilities in 0.0.11](#capabilities-in-0011) — release inventory
- [JS API surface](#js-api-surface) — what every export does
- [Bundle anatomy](#bundle-anatomy) — output shape, sizes, budgets
- [Parameter set](#parameter-set) — ML-KEM-768 only
- [Examples](#examples) — runnable example index

**Operational**

- [When not to use kyberlib-wasm](#when-not-to-use-kyberlib-wasm) — limitations
- [Development](#development) — make targets, wasm-pack workflows
- [Security](#security) — RNG sourcing, CT guarantees, FIPS path
- [Release artefacts](#release-artefacts) — what is and is not signed
- [Documentation](#documentation) — all reference docs
- [License](#license)

---

## Install

### As a JavaScript module (wasm-pack)

There is no npm package. Build the JavaScript module from source
with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/):

```sh
git clone https://github.com/sebastienrousseau/kyberlib.git
cd kyberlib
wasm-pack build crates/kyberlib-wasm --release --target web      # browsers
wasm-pack build crates/kyberlib-wasm --release --target nodejs   # Node.js
wasm-pack build crates/kyberlib-wasm --release --target bundler  # webpack, vite, rollup
```

The output lands in `crates/kyberlib-wasm/pkg/`: the `.wasm` blob,
the JS glue and TypeScript declarations. Copy that directory into
your project, or add it as a local dependency
(`npm install ./path/to/pkg`).

### As a Rust crate (crates.io)

```toml
[dependencies]
kyberlib-wasm = "0.0.11"
```

You need [Rust](https://rustup.rs/) stable ≥ 1.89 (the declared
MSRV) and the `wasm32-unknown-unknown` target. The crate compiles
to a `cdylib`; downstream consumers usually invoke it through
`wasm-pack` rather than `cargo` directly.

### Channels

| Channel | Install |
|---|---|
| JavaScript module | `wasm-pack build crates/kyberlib-wasm --release --target web` (see above) |
| Cargo (crates.io) | `cargo add kyberlib-wasm` |
| Cargo (from source) | `cargo install --locked --path crates/kyberlib-wasm` |

### MSRV

The declared MSRV is **Rust 1.89**, matching the rest of the
kyberlib workspace. A dedicated `msrv` CI job gates this on every
PR.

### Cargo features

`kyberlib-wasm` has no Cargo features. It always builds
ML-KEM-768; see [Parameter set](#parameter-set).

---

## Quick Start

```js
import init, { keypair, encapsulate, decapsulate }
  from './pkg/kyberlib_wasm.js';

await init();   // loads the .wasm and instantiates

// (1) Receiver generates a key pair. `secret` is opaque heap-owned bytes.
const keys = keypair();
console.log('pk', keys.pubkey.length, 'bytes');   // 1184 for ML-KEM-768

// (2) Sender encapsulates a fresh shared secret against the receiver's pk.
const exchange = encapsulate(keys.pubkey);
console.log('ct', exchange.ciphertext.length, 'bytes');   // 1088
console.log('ss', exchange.sharedSecret.length, 'bytes'); // 32

// (3) Receiver decapsulates. Both sides now hold the same 32-byte secret.
const recovered = decapsulate(exchange.ciphertext, keys.secret);
console.assert(
  recovered.every((b, i) => b === exchange.sharedSecret[i]),
  'shared secrets must match'
);

// Free WASM-heap allocations when done (or trust GC in non-loop code).
keys.free();
exchange.free();
```

The same surface works in Node, Deno, Bun, and Cloudflare Workers
with a different build target — see
[`doc/usage.md`](doc/usage.md) for the full bundler matrix and
WebCrypto AES-GCM combiner.

---

## The kyberlib ecosystem

| Crate | What it is | Status (v0.0.11) | Use case |
|---|---|---|---|
| [`kyberlib`](https://crates.io/crates/kyberlib) | Core library — FIPS 203 ML-KEM, no_std + alloc, `#![forbid(unsafe_code)]` (default features) | Published; ACVP 180/180 across ML-KEM-512, -768 and -1024 | Embed ML-KEM in any Rust binary or library. |
| [`kyberlib-asm`](https://crates.io/crates/kyberlib-asm) | AVX2 / NEON / SIMD acceleration backend | Skeleton — [ADR 0002](../../doc/adr/0002-asm-quarantine.md), [#143](https://github.com/sebastienrousseau/kyberlib/issues/143) | High-throughput servers; embedded NEON targets. |
| [`kyberlib-hybrid`](https://crates.io/crates/kyberlib-hybrid) | TLS 1.3 hybrid KEMs — X25519MLKEM768 + ECDHE variants | `X25519MlKem768` wired; ECDHE in [#167b](https://github.com/sebastienrousseau/kyberlib/issues/167) | Direct interop with `draft-ietf-tls-ecdhe-mlkem-04`. |
| [`kyberlib-pkcs8`](https://crates.io/crates/kyberlib-pkcs8) | PKCS#8 / `SubjectPublicKeyInfo` / PEM encoding with LAMPS-registered OIDs | Skeleton — [#168](https://github.com/sebastienrousseau/kyberlib/issues/168) | X.509 cert chains, CMS, PEM exchange. |
| **[`kyberlib-wasm`](https://crates.io/crates/kyberlib-wasm)** | **`wasm-bindgen` wrapper for browser / Node / Cloudflare Workers / Deno** | **Published with `kyberlib`** | **Browser cryptography; built with `wasm-pack`.** |

`kyberlib-wasm` is the JS-side face of the kyberlib library. The
hard cryptography lives in the core `kyberlib` crate — this crate
is a thin marshalling layer that exposes the same public surface
to JavaScript.

---

## Migrating to `kyberlib-wasm`

`kyberlib-wasm` is a drop-in upgrade path for browser apps already
on `@noble/post-quantum` or `@cloudflare/pq`. The byte-level
shapes match (FIPS 203 final), so peers stay interoperable.

### From `@noble/post-quantum`

```diff
-import { ml_kem768 } from '@noble/post-quantum/ml-kem';
+import init, { keypair, encapsulate, decapsulate }
+  from './pkg/kyberlib_wasm.js';
+await init();
```

```diff
-const { secretKey, publicKey } = ml_kem768.keygen();
-const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
-const recovered                    = ml_kem768.decapsulate(cipherText, secretKey);
+const keys     = keypair();
+const exchange = encapsulate(keys.pubkey);
+const recovered = decapsulate(exchange.ciphertext, keys.secret);
```

Wire-format identical (both ship FIPS 203 final). `noble` is pure
JS; `kyberlib-wasm` is compiled Rust → WASM and is ~3–5× faster
in the browser.

### From `@cloudflare/pq`

```diff
-import { mlKem768Keygen, mlKem768Encaps, mlKem768Decaps } from '@cloudflare/pq';
+import init, { keypair, encapsulate, decapsulate }
+  from './pkg/kyberlib_wasm.js';
+await init();
```

The Cloudflare lib also targets FIPS 203; the byte shapes are
identical so existing on-disk keys round-trip without
regeneration.

### From a pre-FIPS-203 Kyber lib (e.g. `kyber-crystals` 2023 builds)

> ⚠️ **Persisted Round-3 keys will NOT seamlessly drop in.** Round
> 3 and FIPS 203 differ in the keygen domain separator, the
> encaps pre-hash, and the rejection KDF — so pre-2024 secret
> keys, ciphertexts, and shared secrets are wire-incompatible
> with `kyberlib-wasm`. You must regenerate keys on both peers
> in lockstep. See [ADR 0001](../../doc/adr/0001-fips203-migration.md)
> for the byte-level deltas.

---

## Why this approach?

`kyberlib-wasm` is the JS face of a Rust library that already
nails the FIPS 203 niche. Splitting the WASM bindings into a
sidecar crate gives the core a clean dependency story and lets
the JS consumers pay only for what they use.

**A thin marshalling layer, not a re-implementation.** Every
crypto operation in `kyberlib-wasm` calls the same audited
primitive in `kyberlib`. The WASM crate adds the
`wasm-bindgen` glue and the `Box<[u8]>` ↔ `Uint8Array` boundary
— nothing else. This means kyberlib-wasm inherits the ACVP
conformance, the KyberSlash audit, the `#![forbid(unsafe_code)]`
discipline of the safe core, and the SLSA L3 + cosign signed
release pipeline. You get the same guarantees in the browser
that you'd get in a native Rust binary.

**The core stays no_std.** `kyberlib` is `#![no_std] + alloc`
under default features. Pulling `wasm-bindgen` and its 14
transitive crates into the core would pollute every native build
that doesn't want WASM. Splitting the binding out keeps the core
small, audit-friendly, and embedded-target compatible — and
keeps `kyberlib-wasm` focused on the browser concerns it actually
owns (bundle size, RNG sourcing, TypedArray ergonomics, JS-GC
lifecycle).

**Predictable bundle size.** The release-gate budget is **150 KiB
compressed** (`brotli -q 11`) for the `.wasm` blob. v0.0.7 sits
at ~122 KiB — ~28 KiB headroom before the gate fails. `wasm-opt
-O3` is part of `wasm-pack`'s release pipeline, so consumers
get the optimised binary by default.

**Browser-native RNG.** kyberlib-wasm pulls entropy from
`crypto.getRandomValues` in browsers and `crypto.randomBytes` in
Node.js, both via `getrandom` 0.2+. You don't plug an RNG in —
the WASM build consults the platform CSPRNG internally. This
matches the ergonomic shape JS callers expect (`keypair()` takes
no args) and avoids the trap of asking app code to choose a CSPRNG
they probably shouldn't pick themselves.

**Release artefacts.** The signed release pipeline (SLSA L3
attestation, cosign signature, CycloneDX CBOM) covers the core
`kyberlib` crate. `kyberlib-wasm` is published to crates.io
without its own signed artefacts; see
[Release artefacts](#release-artefacts).

---

## Capabilities in 0.0.11

| Capability | Status |
|---|---|
| FIPS 203 ML-KEM-768 keygen / encap / decap via JS | ✓ |
| ML-KEM-512 / ML-KEM-1024 | not exposed (ML-KEM-768 only) |
| All three parameter sets in one WASM binary | planned [#180](https://github.com/sebastienrousseau/kyberlib/issues/180) |
| `Uint8Array` byte-slice surface | ✓ |
| TypeScript declarations | ✓ auto-generated by `wasm-bindgen` |
| `crypto.getRandomValues` / `crypto.randomBytes` RNG | ✓ via `getrandom` 0.2+ |
| Browser target (`--target web`) | ✓ |
| Node.js / Deno / Bun (`--target nodejs`) | ✓ |
| Cloudflare Workers (`--target bundler`) | ✓ |
| `wasm32-wasip2` | ✓ compiles cleanly |
| `wasm32-unknown-emscripten` | not supported (use `wasm-bindgen`) |
| Hybrid (X25519MLKEM768) in WASM | planned [#181](https://github.com/sebastienrousseau/kyberlib/issues/181) |
| Bundle size ≤ 150 KiB brotli-compressed | ✓ ~122 KiB on v0.0.7 |
| SLSA L3 + cosign signed releases | core `kyberlib` crate only |
| CycloneDX 1.6 CBOM | core `kyberlib` crate only |

---

## JS API surface

The crate exports four JS-callable functions and two opaque
classes. Everything is `Uint8Array` in, `Uint8Array` out — no
strings, no JSON, no length prefixes.

| JS symbol | Wraps | Returns |
|---|---|---|
| `keypair()` | `kyberlib::keypair` | `Keys { pubkey, secret }` |
| `encapsulate(pk)` | `kyberlib::encapsulate` | `Kex { ciphertext, sharedSecret }` |
| `decapsulate(ct, sk)` | `kyberlib::decapsulate` | `Uint8Array` (32-byte shared secret) |
| `Keys` (class) | typed-buffer pair | `.pubkey: Uint8Array`, `.secret: Uint8Array`, `.free()` |
| `Kex` (class) | typed-buffer pair | `.ciphertext: Uint8Array`, `.sharedSecret: Uint8Array`, `.free()` |

The `keypair()` / `encapsulate()` return values own WASM-allocated
memory. JS's GC eventually reclaims them, but the GC has no
insight into how much WASM linear memory each handle consumes,
so a tight loop can balloon the WASM heap before GC fires. Call
`.free()` explicitly in hot loops; the `pubkey` / `secret` /
`ciphertext` / `sharedSecret` `Uint8Array` fields are **owned
copies**, so you can keep them after the wrapper is freed.

The TypeScript declarations are auto-generated by `wasm-bindgen`
and `wasm-pack` writes them to `pkg/kyberlib_wasm.d.ts`.

---

## Bundle anatomy

A release `wasm-pack build --release` produces:

```text
pkg/
├── kyberlib_wasm.js            JS glue (~7 KiB)
├── kyberlib_wasm_bg.wasm       compiled WASM (~120 KiB after wasm-opt -O3)
├── kyberlib_wasm.d.ts          TypeScript declarations (~3 KiB)
├── package.json                npm metadata (written by wasm-pack)
└── README.md
```

The `--target` flag picks the JS glue's module format:

| Target | Module format | Where it works |
|---|---|---|
| `web` | ESM with `init()` for explicit WASM-load | `<script type="module">` in browsers |
| `nodejs` | CommonJS, eager WASM load | Node.js, Deno (with `node:` shim) |
| `bundler` | ESM with bundler-friendly hooks | webpack, vite, rollup, esbuild |

The `.wasm` file dominates the bundle. The JS glue and TypeScript
declarations are auto-generated and trivially-sized.

### Bundle size budget

The release-gate budget is **150 KiB compressed** (`brotli -q 11`)
for the `.wasm` blob. The CI bench job fails the PR if the budget
regresses.

| Version | `.wasm` (uncompressed) | `.wasm` (brotli -q 11) |
|---|---|---|
| 0.0.7 (this) | ~340 KiB | ~122 KiB |
| 0.0.6 | ~460 KiB | ~190 KiB |

The v0.0.7 trimming came from the tarball-include audit
(`crates/kyberlib-wasm/Cargo.toml::include = [...]`) and from
`wasm-opt -O3` in the release path.

### Cloudflare Workers

WASM module size counts against the 10 MB Workers deployment cap.
At ~122 KiB compressed, `kyberlib-wasm` costs ~1.2% of that
budget. See [`doc/usage.md`](doc/usage.md) for the
`wrangler.toml` wiring and the `--target bundler` invocation.

---

## Parameter set

`kyberlib-wasm` builds **ML-KEM-768** only: it depends on
`kyberlib` with `default-features = false, features = ["kyber768"]`
and has no Cargo features of its own. ML-KEM-512 and ML-KEM-1024
are not exposed to JavaScript; tracked as
[#180](https://github.com/sebastienrousseau/kyberlib/issues/180).

| Item | Size |
|---|---|
| `pubkey` | 1184 B |
| `secret` | 2400 B |
| `ciphertext` | 1088 B |
| `sharedSecret` | 32 B |

---

## Examples

Runnable JS examples live in the `examples/` directory:

| Example | Target | What it shows |
|---|---|---|
| `examples/browser.html` | `--target web` | End-to-end round-trip in a `<script type="module">` block |
| `examples/node.js` | `--target nodejs` | CommonJS round-trip with `Buffer` interop |
| `examples/aead.html` | `--target web` | KEM output ↔ WebCrypto AES-GCM combiner |

Each example is fully commented — explaining *why* each step is
needed (not just *what* the code does). The full bundler matrix
and Cloudflare Workers recipe live in
[`doc/usage.md`](doc/usage.md).

---

## When not to use kyberlib-wasm

`kyberlib-wasm` is the right pick for browser-side ML-KEM with
modern security guarantees. It is **not** the right pick for:

- **Native Rust applications.** Use [`kyberlib`](https://crates.io/crates/kyberlib)
  directly — no `wasm-bindgen` overhead, full typed-state API
  (`MlKem768::generate`, `MlKem768DecapKey`, etc.), `!Copy +
  ZeroizeOnDrop` secret hygiene.
- **Streaming encryption.** ML-KEM is a key encapsulation
  mechanism, not a cipher. Use the 32-byte shared secret as the
  key to a symmetric AEAD (`@noble/ciphers`, `WebCrypto`'s
  AES-GCM); see [`doc/usage.md`](doc/usage.md) for the recipe.
- **Long-running session keys.** The KEM output is a one-shot
  secret. Derive a session key via HKDF
  (`crypto.subtle.deriveBits`) before using it across messages.
- **FIPS 140-3 certified browser cryptography.** WebAssembly
  modules can't be CMVP-validated as a single shipped artefact
  the way native modules can. The `fips` feature (planned for
  the native crate per [ADR 0006](../../doc/adr/0006-fips-facade.md))
  delegates to `aws-lc-rs` and is **not** exposed in WASM —
  see [#170](https://github.com/sebastienrousseau/kyberlib/issues/170).
- **Hybrid KEMs (X25519MLKEM768).** Not yet shipped in WASM —
  tracked as [#181](https://github.com/sebastienrousseau/kyberlib/issues/181).
  For native consumers,
  [`kyberlib-hybrid`](https://crates.io/crates/kyberlib-hybrid)
  has the wired implementation.

---

## Development

```sh
# Build the WASM bundle (release, browser target).
wasm-pack build crates/kyberlib-wasm --release --target web

# Build for Node / Deno / Bun.
wasm-pack build crates/kyberlib-wasm --release --target nodejs

# Build for webpack / vite / rollup.
wasm-pack build crates/kyberlib-wasm --release --target bundler

# Run the wasm-bindgen-test smoke suite (Chrome headless).
wasm-pack test crates/kyberlib-wasm --headless --chrome

# Compile-check for the wasm target.
cargo check -p kyberlib-wasm --target wasm32-unknown-unknown
```

The workspace [`Makefile`](../../Makefile) carries the standard
targets — `make ci`, `make test`, `make doc`, `make bench` — and
all of them include the WASM crate.

---

## Security

`kyberlib-wasm` inherits the security posture of the core
`kyberlib` crate. The thin marshalling layer adds no new
cryptographic surface; the FIPS 203 implementation, the
constant-time properties, and the KyberSlash audit all live in
the audited safe core.

**RNG sourcing.** On `wasm32-unknown-unknown`, `rand::rngs::OsRng`
routes via `getrandom` 0.2+ to `crypto.getRandomValues`
(browsers) or `crypto.randomBytes` (Node.js). Both surfaces are
seeded from the host OS CSPRNG. The WASM build does not accept
caller-supplied entropy — by design, since browser JS doesn't
have a safe way to pass it.

**Constant-time guarantees.** The reference backend in
`kyberlib` uses the upstream pq-crystals Barrett-style
multiply-and-shift; there are no `udiv` / `sdiv` instructions
on secret inputs anywhere in the source tree
([ADR 0003](../../doc/adr/0003-kyberslash-audit.md)). The
KyberSlash regression gate (`scripts/kyberslash-guard.sh`)
runs on every PR.

**Implicit rejection.** FIPS 203 §6.3 implicit rejection means
`decapsulate` returns a pseudorandom shared secret on a tampered
ciphertext — it does **not** return an error. This is the
correct behaviour for protocol designers; do not branch on
"decap succeeded" without verifying the recovered shared secret
against an authenticated tag.

See the workspace [`SECURITY.md`](../../SECURITY.md) for the
full threat model, the constant-time guarantees table, and the
audit posture.

---

## Release artefacts

Every `v*.*.*` tag triggers the release pipeline at
[`.github/workflows/release.yml`](../../.github/workflows/release.yml).
It signs and attests the **core `kyberlib` `.crate`** (SLSA L3
provenance, keyless cosign signature, CycloneDX 1.6 CBOM); the
verification recipes are in the
[workspace README](../../README.md#release-artefacts).

`kyberlib-wasm` itself is published to crates.io only. There is
no signed `kyberlib-wasm` `.crate`, no pre-built `.wasm` and no
npm package on the GitHub release; build the JavaScript module
with `wasm-pack` as shown in [Install](#install).

---

## Documentation

| Document | What it covers |
|---|---|
| [`doc/architecture.md`](doc/architecture.md) | Why a sidecar crate, surface design, bundle anatomy, RNG sourcing, target matrix |
| [`doc/usage.md`](doc/usage.md) | Browser / Node / Deno / Bun / Cloudflare Workers integration; AES-GCM combiner; TypeScript; resource management |
| [`../../README.md`](../../README.md) | Workspace root README (full FIPS 203 + ecosystem context) |
| [`../../doc/COMPARISON.md`](../../doc/COMPARISON.md) | kyberlib vs. competing Rust ML-KEM crates |
| [`../../doc/BENCHMARKS.md`](../../doc/BENCHMARKS.md) | criterion + dudect numbers + reproduction recipe |
| [`../../SECURITY.md`](../../SECURITY.md) | Threat model, CT guarantees, audit posture, FIPS path |
| [`../../doc/adr/`](../../doc/adr/) | Architecture decision records (FIPS 203, asm quarantine, KyberSlash, multi-param, BYOE deterministic API, FIPS facade) |

---

## License

`kyberlib-wasm` is dual-licensed under either of:

- [Apache License, Version 2.0](../../LICENSE-APACHE)
  ([http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
- [MIT License](../../LICENSE-MIT)
  ([http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))

at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in the work,
as defined in the Apache-2.0 license, shall be dual-licensed as
above, without any additional terms or conditions.

REUSE-compliant SPDX headers are present on every source file in
the workspace; see the per-crate `LICENSES/` directory and the
workspace [`REUSE.toml`](../../REUSE.toml) for the machine-
readable licensing metadata.
