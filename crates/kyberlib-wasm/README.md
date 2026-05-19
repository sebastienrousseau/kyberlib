# kyberlib-wasm

WebAssembly bindings for [`kyberlib`](https://crates.io/crates/kyberlib),
the FIPS 203 ML-KEM (post-quantum key encapsulation mechanism)
Rust library.

## Quick start

```sh
wasm-pack build --target web crates/kyberlib-wasm
```

The output `pkg/` directory carries the `.wasm`, the JS shim, and
TypeScript types. Drop it into a browser app:

```js
import init, { keypair, encapsulate, decapsulate } from './pkg/kyberlib_wasm.js';

await init();

const keys = keypair();
const { ciphertext, sharedSecret } = encapsulate(keys.pubkey);
const recovered = decapsulate(ciphertext, keys.secret);
console.assert(recovered === sharedSecret);
```

## What's exposed

| JS symbol              | Wraps                       |
|------------------------|-----------------------------|
| `keypair()`            | `kyberlib::keypair`         |
| `encapsulate(pk)`      | `kyberlib::encapsulate`     |
| `decapsulate(ct, sk)`  | `kyberlib::decapsulate`     |
| `Keys` (class)         | `MlKem768EncapKey` / `DecapKey` blob |
| `Kex` (class)          | `(ct, ss)` pair             |
| `Params` (class)       | The byte-size constants     |

## Status

This crate ships in lockstep with `kyberlib` (the workspace's
`[workspace.package].version`). Like the core crate, it carries
the FIPS 203 ML-KEM-768 conformance landed in v0.0.7 (see the
root [CHANGELOG](../../CHANGELOG.md)).

For native (non-WASM) consumers, use `kyberlib` directly. The
`kyberlib-wasm` shim exists only to expose the same API surface
to JavaScript via `wasm-bindgen`.

## License

Dual-licensed under either of [MIT](../../LICENSE-MIT) or
[Apache 2.0](../../LICENSE-APACHE) at your option.
