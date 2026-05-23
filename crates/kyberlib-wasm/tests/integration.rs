// Copyright © 2024-2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! WebAssembly integration tests for `kyberlib-wasm`. Runs only on the
//! `wasm32-unknown-unknown` target via `wasm-bindgen-test` (e.g.
//! `wasm-pack test --headless --firefox` from this crate's directory).
//!
//! Native `cargo test` builds are skipped here — the module-level
//! `#![cfg(target_arch = "wasm32")]` makes the file empty under host
//! compilation, so `cargo test --workspace` from the repo root remains
//! green without needing a wasm toolchain.

#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod tests {
    use kyberlib::{decapsulate, encapsulate, keypair, params::*};
    use kyberlib_wasm::{Kex, Keys, Params};
    use wasm_bindgen_test::*;

    // Configure wasm-bindgen-test for browser execution
    wasm_bindgen_test_configure!(run_in_browser);

    // Test the keypair function
    #[wasm_bindgen_test]
    fn test_keypair() {
        // Generate a key pair using a random number generator
        let mut rng = rand::rngs::OsRng {};
        let result = keypair(&mut rng);
        assert!(result.is_ok());
    }

    // Test the encapsulate function.
    //
    // Note (v0.0.7): `kyberlib::encapsulate` only validates the
    // public key's BYTE LENGTH — not its mathematical structure.
    // Any length-correct byte string (including all zeros) is
    // accepted as a public key by the spec. The legitimate failure
    // mode is wrong-length input; we test that here.
    #[wasm_bindgen_test]
    fn test_encapsulate() {
        let mut rng = rand::rngs::OsRng {};

        // Wrong length — must surface InvalidInput.
        let bad_pk =
            vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1].into_boxed_slice();
        assert!(
            encapsulate(&bad_pk, &mut rng).is_err(),
            "encap must reject a too-short public key"
        );

        // Length-valid (even if all-zero) pk → encapsulation
        // succeeds. The byte structure is the caller's concern.
        let valid_len_pk =
            vec![0u8; KYBER_PUBLIC_KEY_BYTES].into_boxed_slice();
        assert!(
            encapsulate(&valid_len_pk, &mut rng).is_ok(),
            "encap must accept any length-correct pk byte string"
        );

        // Realistic happy path with a fresh keypair.
        let keys = keypair(&mut rng).expect("keypair must succeed");
        assert!(
            encapsulate(&keys.public, &mut rng).is_ok(),
            "encap must succeed against a freshly-generated pk"
        );
    }

    // Test the decapsulate function.
    //
    // Note (v0.0.7): per FIPS 203 §6.3 **implicit rejection**,
    // decapsulating a length-valid but tampered/wrong ciphertext
    // returns a *pseudorandom* shared secret rather than an error.
    // This is the property that defeats Bleichenbacher-style
    // decapsulation oracles. So `decapsulate` ONLY errors on
    // length-mismatched input, never on bad bytes.
    #[wasm_bindgen_test]
    fn test_decapsulate() {
        let mut rng = rand::rngs::OsRng {};

        // Wrong length — must surface InvalidInput.
        let bad_ct =
            vec![0u8; KYBER_CIPHERTEXT_BYTES - 1].into_boxed_slice();
        let sk = vec![0u8; KYBER_SECRET_KEY_BYTES].into_boxed_slice();
        assert!(
            decapsulate(&bad_ct, &sk).is_err(),
            "decap must reject a too-short ciphertext"
        );

        // Length-valid ciphertext + length-valid sk → decap
        // returns Ok with a pseudorandom 32-byte secret (implicit
        // rejection). No error.
        let valid_len_ct =
            vec![0u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let ss = decapsulate(&valid_len_ct, &sk)
            .expect("implicit rejection must NOT surface an error");
        assert_eq!(
            ss.len(),
            KYBER_SHARED_SECRET_BYTES,
            "implicit-rejection output is still 32 bytes"
        );

        // Realistic happy path: fresh keys → fresh kex → decap.
        let keys = keypair(&mut rng).expect("keypair must succeed");
        let (ct, ss_sender) = encapsulate(&keys.public, &mut rng)
            .expect("encap must succeed");
        let ss_receiver =
            decapsulate(&ct, &keys.secret).expect("decap must succeed");
        assert_eq!(
            ss_sender, ss_receiver,
            "valid round-trip must recover the same shared secret"
        );
    }

    // Test the Keys struct
    #[wasm_bindgen_test]
    fn test_keys() {
        // Create a new Keys instance
        let keys = Keys::new().unwrap_or_else(|_| {
            panic!("Failed to create Keys instance")
        });

        // Ensure the public key and secret key have expected lengths
        assert_eq!(keys.pubkey().len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keys.secret().len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test the Kex struct
    #[wasm_bindgen_test]
    fn test_kex() {
        // Create a new Keys instance
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => {
                // If Keys::new() fails, skip the test
                return;
            }
        };

        // Create a new Kex instance using the valid public key
        let mut kex = Kex::new(keys.pubkey());

        // Test the ciphertext and sharedSecret getters
        assert_eq!(kex.ciphertext().len(), KYBER_CIPHERTEXT_BYTES);
        assert_eq!(kex.sharedSecret().len(), KYBER_SHARED_SECRET_BYTES);

        // Test the set_ciphertext and set_sharedSecret methods
        let new_ct =
            vec![0u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let new_ss =
            vec![0u8; KYBER_SHARED_SECRET_BYTES].into_boxed_slice();
        kex.set_ciphertext(new_ct.clone());
        kex.set_sharedSecret(new_ss.clone());
        assert_eq!(kex.ciphertext(), new_ct);
        assert_eq!(kex.sharedSecret(), new_ss);
    }

    // Test the Kex new method
    #[wasm_bindgen_test]
    fn test_kex_new() {
        // Create a new Keys instance
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => {
                // If Keys::new() fails, skip the test
                return;
            }
        };

        // Ensure the ciphertext and shared secret have expected lengths
        assert_eq!(keys.pubkey().len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keys.secret().len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test the Params struct
    #[wasm_bindgen_test]
    fn test_params() {
        // Ensure the parameter values match the expected constants
        assert_eq!(Params::publicKeyBytes(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(Params::secretKeyBytes(), KYBER_SECRET_KEY_BYTES);
        assert_eq!(Params::ciphertextBytes(), KYBER_CIPHERTEXT_BYTES);
        assert_eq!(
            Params::sharedSecretBytes(),
            KYBER_SHARED_SECRET_BYTES
        );
    }

    // Test that `encapsulate` rejects wrong-length public keys.
    //
    // Note: the original test relied on `std::panic::catch_unwind`
    // to catch the panic from `Kex::new()`, which calls
    // `encapsulate(pk).expect(...)`. That doesn't work on
    // `wasm32-unknown-unknown` because wasm panics abort rather
    // than unwind. We test the same property by calling the
    // non-panicking free function `encapsulate` directly.
    #[wasm_bindgen_test]
    fn test_encapsulate_rejects_short_public_key() {
        let invalid_pk =
            vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1].into_boxed_slice();
        let mut rng = rand::rngs::OsRng {};
        assert!(
            encapsulate(&invalid_pk, &mut rng).is_err(),
            "encapsulate must reject a too-short public key"
        );
    }

    // Test decapsulation with a ciphertext encapsulated against a
    // DIFFERENT key pair than the one we hold.
    //
    // Per FIPS 203 §6.3 **implicit rejection**, this returns a
    // pseudorandom 32-byte secret — NOT an error. The receiver
    // can't distinguish "tampered ciphertext" from "honest
    // ciphertext" via the decap return channel; the only way to
    // detect a mismatch is to compare the recovered secret
    // against an out-of-band authentication tag.
    //
    // This test asserts the implicit-rejection contract.
    #[wasm_bindgen_test]
    fn test_decapsulate_mismatched_inputs() {
        let alice = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };
        let kex_for_alice = Kex::new(alice.pubkey());

        // Eve holds a different key pair and tries to decap the
        // ciphertext intended for Alice.
        let eve = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        let eve_ss =
            decapsulate(&kex_for_alice.ciphertext(), &eve.secret())
                .expect("implicit rejection MUST NOT surface an error");

        assert_eq!(
            eve_ss.len(),
            KYBER_SHARED_SECRET_BYTES,
            "implicit-rejection output is still 32 bytes"
        );
        assert_ne!(
            eve_ss.as_ref(),
            kex_for_alice.sharedSecret().as_ref(),
            "Eve must NOT recover Alice's shared secret (would be \
             a confidentiality break)"
        );
    }

    // Test the decapsulate() function with a valid ciphertext and secret key
    #[wasm_bindgen_test]
    fn test_decapsulate_valid_inputs() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Encapsulate with the public key to get a valid ciphertext
        let kex = Kex::new(keys.pubkey());

        // Call decapsulate() with the valid ciphertext and secret key
        let result = decapsulate(&kex.ciphertext(), &keys.secret());
        assert!(result.is_ok());
    }

    // Test the decapsulate() function with an invalid ciphertext size
    #[wasm_bindgen_test]
    fn test_decapsulate_invalid_ciphertext_size() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Create an invalid ciphertext with incorrect size
        let invalid_ct =
            vec![0u8; KYBER_CIPHERTEXT_BYTES - 1].into_boxed_slice();

        // Call decapsulate() with the invalid ciphertext and valid secret key
        let result = decapsulate(&invalid_ct, &keys.secret());
        assert!(result.is_err());
    }

    // Test the decapsulate() function with an invalid secret key size
    #[wasm_bindgen_test]
    fn test_decapsulate_invalid_secret_key_size() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Encapsulate with the public key to get a valid ciphertext
        let kex = Kex::new(keys.pubkey());

        // Create an invalid secret key with incorrect size
        let invalid_sk =
            vec![0u8; KYBER_SECRET_KEY_BYTES - 1].into_boxed_slice();

        // Call decapsulate() with the valid ciphertext and invalid secret key
        let result = decapsulate(&kex.ciphertext(), &invalid_sk);
        assert!(result.is_err());
    }

    // Test the Keys struct's pubkey() and secret() methods
    #[wasm_bindgen_test]
    fn test_keys_methods() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Check if pubkey() returns the expected public key
        assert_eq!(keys.pubkey().len(), KYBER_PUBLIC_KEY_BYTES);

        // Check if secret() returns the expected secret key
        assert_eq!(keys.secret().len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test the Kex struct's ciphertext(), sharedSecret(), set_ciphertext(), and set_sharedSecret() methods
    #[wasm_bindgen_test]
    fn test_kex_methods() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Create a Kex instance
        let mut kex = Kex::new(keys.pubkey());

        // Check if ciphertext() returns the expected ciphertext
        assert_eq!(kex.ciphertext().len(), KYBER_CIPHERTEXT_BYTES);

        // Check if sharedSecret() returns the expected shared secret
        assert_eq!(kex.sharedSecret().len(), KYBER_SHARED_SECRET_BYTES);

        // Create new ciphertext and shared secret
        let new_ct =
            vec![1u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let new_ss =
            vec![2u8; KYBER_SHARED_SECRET_BYTES].into_boxed_slice();

        // Set the new ciphertext and shared secret
        kex.set_ciphertext(new_ct.clone());
        kex.set_sharedSecret(new_ss.clone());

        // Check if the ciphertext and shared secret are updated correctly
        assert_eq!(kex.ciphertext(), new_ct);
        assert_eq!(kex.sharedSecret(), new_ss);
    }

    // Test the encapsulate() function with a valid public key and an invalid RNG
    #[wasm_bindgen_test]
    fn test_encapsulate_invalid_rng() {
        // Generate a valid key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Create a mock RNG that always returns an error
        #[allow(dead_code)]
        struct MockRng;
        impl rand_core::RngCore for MockRng {
            fn next_u32(&mut self) -> u32 {
                0
            }
            fn next_u64(&mut self) -> u64 {
                0
            }
            fn fill_bytes(&mut self, _dest: &mut [u8]) {}

            fn try_fill_bytes(
                &mut self,
                _dest: &mut [u8],
            ) -> Result<(), rand_core::Error> {
                // `rand_core::Error::new` was removed in 0.6 — the
                // public constructor surface is now `From<NonZeroU32>`.
                // The error code itself is opaque to callers; any
                // non-zero value identifies "synthetic test failure".
                Err(rand_core::Error::from(
                    core::num::NonZeroU32::new(
                        rand_core::Error::CUSTOM_START + 1,
                    )
                    .unwrap(),
                ))
            }
        }
        impl rand_core::CryptoRng for MockRng {}

        // Call encapsulate() with the valid public key and the mock RNG.
        let result = encapsulate(&keys.pubkey(), &mut MockRng);
        assert!(result.is_err());
    }
}
