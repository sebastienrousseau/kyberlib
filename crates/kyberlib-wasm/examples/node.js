// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Node.js example for kyberlib-wasm — runnable from a Node 18+
// installation after running:
//
//     wasm-pack build crates/kyberlib-wasm --release --target nodejs
//
// Then:
//
//     node crates/kyberlib-wasm/examples/node.js
//
// The example walks through the full ML-KEM-768 round-trip and uses
// Node's `Buffer` to demonstrate interop with idiomatic Node APIs.
// Entropy comes from `crypto.randomBytes` via the OS CSPRNG, surfaced
// through `getrandom` 0.2+ inside the WASM module.

'use strict';

const path = require('path');
const { keypair, encapsulate, decapsulate } = require(
  path.join(__dirname, '..', 'pkg', 'kyberlib_wasm.js')
);

function main() {
  // (1) Receiver: generate a key pair. The WASM wrapper internally
  //     pulls 64 bytes from `crypto.randomBytes` for FIPS 203 §5.1
  //     `(d, z)`.
  const keys = keypair();
  console.log('pubkey bytes:', keys.pubkey.length);     // 1184
  console.log('secret bytes:', keys.secret.length);     // 2400

  // (2) Sender: encapsulate against the receiver's public key.
  //     `encapsulate` returns a `Kex` object with `ciphertext` and
  //     `sharedSecret` `Uint8Array` fields.
  const exchange = encapsulate(keys.pubkey);
  console.log('ciphertext bytes:', exchange.ciphertext.length);   // 1088
  console.log('sharedSecret bytes:', exchange.sharedSecret.length); // 32

  // (3) Receiver: decapsulate. Returns a 32-byte `Uint8Array` —
  //     identical to the sender's secret on a well-formed CT,
  //     pseudorandom on a tampered one (FIPS 203 §6.3 implicit
  //     rejection).
  const recovered = decapsulate(exchange.ciphertext, keys.secret);

  // (4) Confirm both sides agree. We convert to `Buffer` to
  //     demonstrate the Node interop pattern — `Buffer.equals` is
  //     constant-time on the byte comparison itself.
  const sender = Buffer.from(exchange.sharedSecret);
  const receiver = Buffer.from(recovered);

  if (sender.equals(receiver)) {
    console.log('shared secrets match ✓');
  } else {
    console.error('shared secrets DO NOT match ✗');
    process.exit(1);
  }

  // (5) Free the WASM-heap allocations promptly. In a long-running
  //     server you'd do this on every connection; in a one-shot
  //     script it's polite but not critical.
  keys.free();
  exchange.free();
}

main();
