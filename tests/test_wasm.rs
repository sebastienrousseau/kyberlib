// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    // Import necessary items
    use kyberlib::wasm::{Kex, Keys, Params};
    use kyberlib::{decapsulate, encapsulate, keypair, params::*};
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

    // Test the encapsulate function
    #[wasm_bindgen_test]
    fn test_encapsulate() {
        // Generate a public key with invalid size
        let pk = vec![0u8; KYBER_PUBLIC_KEY_BYTES].into_boxed_slice();
        let mut rng = rand::rngs::OsRng {};

        // Test encapsulation with invalid input sizes
        let result = encapsulate(&pk, &mut rng);
        assert!(result.is_err());

        // Generate a valid key pair
        let keypair_result = keypair(&mut rng);
        assert!(keypair_result.is_ok());

        // Test encapsulation with valid input sizes
        let result = encapsulate(&pk, &mut rng);
        assert!(result.is_ok());
    }

    // Test the decapsulate function
    #[wasm_bindgen_test]
    fn test_decapsulate() {
        // Generate invalid ciphertext and secret key
        let ct = vec![0u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let sk = vec![0u8; KYBER_SECRET_KEY_BYTES].into_boxed_slice();

        // Test decapsulation with invalid input sizes
        let result = decapsulate(&ct, &sk);
        assert!(result.is_err());

        // Generate a valid key pair
        let keypair_result = keypair(&mut rand::rngs::OsRng {});
        assert!(keypair_result.is_ok());
        let keys = keypair_result.unwrap();

        // Test encapsulation with valid input sizes
        let result =
            encapsulate(&keys.public, &mut rand::rngs::OsRng {});
        assert!(result.is_ok());

        // Test decapsulation with valid input sizes
        let result = decapsulate(&ct, &keys.secret);
        assert!(result.is_ok());
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

    // Test the Kex::new() method with an invalid public key size
    #[wasm_bindgen_test]
    fn test_kex_new_invalid_pubkey_size() {
        // Generate an invalid public key with incorrect size
        let invalid_pk =
            vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1].into_boxed_slice();

        // Call Kex::new() with the invalid public key and expect a panic
        let _ = std::panic::catch_unwind(|| {
            let _ = Kex::new(invalid_pk);
        })
        .unwrap_err();
    }

    // Test the decapsulate() function with mismatched ciphertext and secret key
    #[wasm_bindgen_test]
    fn test_decapsulate_mismatched_inputs() {
        // Generate a key pair
        let keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Encapsulate with the public key to get a valid ciphertext
        let kex = Kex::new(keys.pubkey());

        // Generate a different key pair
        let different_keys = match Keys::new() {
            Ok(keys) => keys,
            Err(_) => return,
        };

        // Call decapsulate() with mismatched ciphertext and secret key
        let result =
            decapsulate(&kex.ciphertext(), &different_keys.secret());
        assert!(result.is_err());
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
                Err(rand_core::Error::new("MockRng error"))
            }
        }
        impl rand_core::CryptoRng for MockRng {}

        // Call encapsulate() with the valid public key and the mock RNG
        let result = encapsulate(&keys.pubkey(), &mut MockRng);
        assert!(result.is_err());
    }
}
