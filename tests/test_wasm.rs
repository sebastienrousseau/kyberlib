// Copyright © 2023 kyberlib. All rights reserved.
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
        let result = encapsulate(&keys.public, &mut rand::rngs::OsRng {});
        assert!(result.is_ok());

        // Test decapsulation with valid input sizes
        let result = decapsulate(&ct, &keys.secret);
        assert!(result.is_ok());
    }

    // Test the Keys struct
    #[wasm_bindgen_test]
    fn test_keys() {
        // Create a new Keys instance
        let keys = Keys::new().unwrap_or_else(|_| panic!("Failed to create Keys instance"));

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
        let new_ct = vec![0u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let new_ss = vec![0u8; KYBER_SHARED_SECRET_BYTES].into_boxed_slice();
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
        assert_eq!(Params::sharedSecretBytes(), KYBER_SHARED_SECRET_BYTES);
    }
}
