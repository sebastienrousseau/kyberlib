# Usage

> Last Updated: 2026-05-22

Practical guide for consuming `kyberlib-wasm` from
JavaScript, TypeScript, Deno, Bun, and Cloudflare Workers.
For the design rationale see
[`architecture.md`](./architecture.md).

## Build

```sh
# One-shot npm package:
wasm-pack build --release --target web   # for browsers
wasm-pack build --release --target nodejs  # for Node.js / Deno / Bun
wasm-pack build --release --target bundler # for webpack / vite / rollup
```

The `--target` flag picks the JS glue's module format:

| Target | Module format | Where it works |
|---|---|---|
| `web` | ESM with `init()` for explicit WASM-load | `<script type="module">` in browsers |
| `nodejs` | CommonJS, eager WASM load | Node.js, Deno (with `node:` shim) |
| `bundler` | ESM with bundler-friendly hooks | webpack, vite, rollup, esbuild |

The output lands in `pkg/`. Drop the whole directory into
your front-end's `node_modules/` or publish it to npm.

## Browser example (`--target web`)

```html
<!DOCTYPE html>
<script type="module">
  import init, { keypair, encapsulate, decapsulate }
    from "./pkg/kyberlib_wasm.js";

  await init();   // Loads the .wasm and instantiates.

  const keys = keypair();
  console.log("pk", keys.pubkey.length, "bytes");
  console.log("sk", keys.secret.length, "bytes");

  const exchange = encapsulate(keys.pubkey);
  console.log("ct", exchange.ciphertext.length, "bytes");
  console.log("ss", exchange.sharedSecret.length, "bytes");

  const sharedSecretBob = decapsulate(exchange.ciphertext, keys.secret);
  console.log("match?",
    sharedSecretBob.every((b, i) => b === exchange.sharedSecret[i])
  );
</script>
```

## Node.js example (`--target nodejs`)

```js
const { keypair, encapsulate, decapsulate } = require("./pkg/kyberlib_wasm");

const keys = keypair();
const { ciphertext, sharedSecret } = encapsulate(keys.pubkey);
const ssBob = decapsulate(ciphertext, keys.secret);

console.log(Buffer.from(sharedSecret).equals(Buffer.from(ssBob)));
```

## TypeScript

`wasm-pack` emits `pkg/kyberlib_wasm.d.ts` with declarations
for every export:

```ts
export function keypair(): Keys;
export function encapsulate(pk: Uint8Array): Kex;
export function decapsulate(ct: Uint8Array, sk: Uint8Array): Uint8Array;

export class Keys {
  readonly pubkey: Uint8Array;
  readonly secret: Uint8Array;
  free(): void;
}

export class Kex {
  readonly ciphertext: Uint8Array;
  readonly sharedSecret: Uint8Array;
  free(): void;
}
```

Note `Keys` and `Kex` are opaque WASM-allocated objects;
remember to call `.free()` when you're done to release the
WASM heap allocation (or trust the GC if you're not in a
tight loop — see the *resource management* note below).

## Byte sizes per parameter set

The default build is **ML-KEM-768**:

| Item | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| Public key (`pubkey`) | 800 B | 1184 B | 1568 B |
| Secret key (`secret`) | 1632 B | 2400 B | 3168 B |
| Ciphertext (`ciphertext`) | 768 B | 1088 B | 1568 B |
| Shared secret (`sharedSecret`) | 32 B | 32 B | 32 B |

To compile for ML-KEM-512 / 1024 see the note in
[`architecture.md`](./architecture.md#parameter-set).

## Combining with WebCrypto AES-GCM

ML-KEM's 32-byte shared secret feeds straight into
`AES-GCM` via `crypto.subtle.importKey`:

```js
import init, { keypair, encapsulate, decapsulate }
  from "./pkg/kyberlib_wasm.js";
await init();

async function encryptForRecipient(recipientPubkey, plaintext) {
  const { ciphertext, sharedSecret } = encapsulate(recipientPubkey);

  const key = await crypto.subtle.importKey(
    "raw", sharedSecret,
    { name: "AES-GCM", length: 256 },
    false, ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return { ciphertext, iv, encrypted: new Uint8Array(encrypted) };
}
```

For multi-message sessions, derive a session key via
HKDF (`crypto.subtle.deriveBits`) rather than using the
KEM output directly.

## Resource management

The `Keys` and `Kex` types own WASM-allocated memory.
JavaScript's GC eventually reclaims them, but the JS GC
has no insight into how much WASM memory each handle
consumes — so a tight loop can balloon the WASM heap
before GC kicks in.

**Best practice**: call `.free()` explicitly when you're
done with a `Keys` / `Kex` object, especially inside loops:

```js
function processBatch(recipients) {
  for (const pk of recipients) {
    const kex = encapsulate(pk);
    sendOnWire(kex.ciphertext);
    storeSecret(kex.sharedSecret);
    kex.free();   // ← free promptly
  }
}
```

The `keypair()` return value's `pubkey` and `secret`
fields are **owned copies** (the WASM heap is freed when
you `.free()` the wrapper), so you can keep the
`Uint8Array` references after calling `.free()`.

## Cloudflare Workers

`kyberlib-wasm` works in Cloudflare Workers via the
`--target bundler` build path:

```js
// wrangler.toml
//   [build]
//   command = "wasm-pack build crates/kyberlib-wasm --release --target bundler"

import wasmModule from "./pkg/kyberlib_wasm_bg.wasm";
import { __wbg_set_wasm } from "./pkg/kyberlib_wasm_bg.js";

const wasm = await WebAssembly.instantiate(wasmModule);
__wbg_set_wasm(wasm.instance.exports);

export default {
  async fetch(req) {
    const { encapsulate } = await import("./pkg/kyberlib_wasm.js");
    /* ... */
  }
};
```

Workers count WASM module size against the 10 MB
deployment cap; at ~120 KiB compressed, `kyberlib-wasm`
costs ~1% of that budget.

## Common pitfalls

1. **Forgetting `.free()`** in long-running loops →
   memory leak in the WASM linear memory.
2. **Treating `Uint8Array` as a string** → use
   `TextEncoder` / `TextDecoder` for string ↔ byte
   conversion; do NOT pass strings to
   `encapsulate(pk)`.
3. **Calling functions before `await init()`** in `--target
   web` builds → `RuntimeError: unreachable`. Always wait
   for the init Promise.
4. **Mixing parameter sets across peers**. The WASM build
   has one parameter set baked in. If Alice's browser is
   built for ML-KEM-768 and Bob's for ML-KEM-1024, byte
   lengths don't match — `decapsulate` returns
   `InvalidInput`.

## See also

* `tests/wasm_smoke.rs` (if present) — runnable round-trip
  smoke test under `wasm-bindgen-test`.
* [`architecture.md`](./architecture.md) — design and
  surface rationale.
* `crates/kyberlib/doc/cookbook.md` — non-WASM cookbook
  whose recipes also apply to JS once you've crossed the
  WASM boundary.
