<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Migrating to kyberlib

kyberlib implements **FIPS 203 ML-KEM** (NIST, August 2024)
— the standardised form of CRYSTALS-Kyber Round 3. v0.0.6 and
earlier shipped the Round-3 surface. The byte-level deltas
(K-byte domain separator, dropped `m' = H(m)` pre-hash, dropped
final KDF + `J(z‖c)` rejection branch) are documented in
[ADR 0001](adr/0001-fips203-migration.md). Migration paths:

## From kyberlib 0.0.6 → 0.0.7

> ⚠️ **Persisted v0.0.6 key material will NOT seamlessly drop in to v0.0.7.**
> Round 3 and FIPS 203 differ in the keygen domain separator, the
> encaps pre-hash, and the rejection KDF — so 0.0.6 secret keys,
> ciphertexts, and shared secrets are wire-incompatible with 0.0.7.
> You **must regenerate keys** on both peers in lockstep.

```diff
-[dependencies]
-kyberlib = "0.0.6"
+[dependencies]
+kyberlib = "0.0.16"
```

```diff
-let keys = kyberlib::keypair(&mut rng)?;
-let (ct, ss_a) = kyberlib::encapsulate(&keys.public, &mut rng)?;
-let ss_b = kyberlib::decapsulate(&ct, &keys.secret)?;
+let (dk, ek) = kyberlib::MlKem768::generate(&mut rng)?;     // typed
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);                              // no Result
```

The free-function surface (`keypair` / `encapsulate` / `decapsulate`)
still works — it's soft-deprecated and delegates to the typed API.
Shared-secret bytes change vs. 0.0.6 because of the FIPS 203
spec migration; this is **intentional** and required for interop
with every other FIPS 203 endpoint.

## From `pqcrypto-kyber`

```diff
-[dependencies]
-pqcrypto-kyber = "0.8"
+[dependencies]
+kyberlib = "0.0.16"
```

```diff
-use pqcrypto_kyber::kyber768::{keypair, encapsulate, decapsulate};
-let (pk, sk) = keypair();
-let (ss_a, ct) = encapsulate(&pk);
-let ss_b = decapsulate(&ct, &sk);
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);
```

`pqcrypto-kyber` is Round-3 and marked unmaintained. Shared
secrets, ciphertexts, and public keys are byte-incompatible with
FIPS 203. Migrating requires re-generating any persisted
key material.

## From `RustCrypto/ml-kem`

```diff
-[dependencies]
-ml-kem = "0.3"
+[dependencies]
+kyberlib = "0.0.16"
```

```diff
-use ml_kem::{MlKem768, KemCore};
-use ml_kem::kem::{Encapsulate, Decapsulate};
-let (dk, ek) = MlKem768::generate(&mut rng);
-let (ct, k_sender) = ek.encapsulate(&mut rng).unwrap();
-let k_receiver = dk.decapsulate(&ct).unwrap();
+use kyberlib::{MlKem768, KemCore};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, k_sender) = ek.encapsulate(&mut rng)?;
+let k_receiver = dk.decapsulate(&ct);  // no Result — implicit rejection
```

API shapes are deliberately convergent. Notable behavioural
differences listed in [`COMPARISON.md`](COMPARISON.md).

## From `libcrux-ml-kem`

```diff
-[dependencies]
-libcrux-ml-kem = "0.0"
+[dependencies]
+kyberlib = "0.0.16"
```

Function-name table:

| `libcrux-ml-kem` | `kyberlib` |
|---|---|
| `libcrux_ml_kem::mlkem768::generate_key_pair_unpacked(seed)` | `MlKem768::generate(&mut rng)` |
| `libcrux_ml_kem::mlkem768::encapsulate(ek, randomness)` | `ek.encapsulate(&mut rng)` |
| `libcrux_ml_kem::mlkem768::decapsulate(dk, ct)` | `dk.decapsulate(&ct)` |
| (`MlKemPublicKey<{1184}>`) | `MlKem768EncapKey` |
| (`MlKemPrivateKey<{2400}>`) | `MlKem768DecapKey` |
| (`MlKemCiphertext<{1088}>`) | `MlKem768Ciphertext` |

libcrux ships F\* + hax-verified primitives. kyberlib reserves a
`verified` feature for a libcrux backend
([#171](https://github.com/sebastienrousseau/kyberlib/issues/171)); it is
a no-op today.

## From `oqs` / `oqs-rs`

```diff
-[dependencies]
-oqs = "0.10"
+[dependencies]
+kyberlib = "0.0.16"
```

```diff
-use oqs::kem::{Kem, Algorithm};
-let kem = Kem::new(Algorithm::MlKem768)?;
-let (pk, sk) = kem.keypair()?;
-let (ct, ss_a) = kem.encapsulate(&pk)?;
-let ss_b = kem.decapsulate(&sk, &ct)?;
+use kyberlib::{KemCore, MlKem768};
+let (dk, ek) = MlKem768::generate(&mut rng)?;
+let (ct, ss_a) = ek.encapsulate(&mut rng)?;
+let ss_b = dk.decapsulate(&ct);
```

`liboqs` is a C library used through FFI; kyberlib is pure Rust.
