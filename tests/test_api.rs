// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Import necessary modules
use kyberlib::*;
use rand::rngs::OsRng;

// Unit tests module
#[cfg(test)]
mod tests {
    // Import necessary items from the parent module
    use super::*;

    // Test for keypair generation
    #[test]
    fn test_keypair_generation() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Assert the length of the public and secret keys
        assert_eq!(keypair.public.len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret.len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test for encapsulation and decapsulation
    #[test]
    fn test_encapsulate_decapsulate() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Encapsulate a shared secret
        let (ciphertext, shared_secret1) = encapsulate(&keypair.public, &mut rng).unwrap();
        // Decapsulate the shared secret
        let shared_secret2 = decapsulate(&ciphertext, &keypair.secret).unwrap();
        // Assert equality of the shared secrets
        assert_eq!(shared_secret1, shared_secret2);
    }

    // Test for keypair derivation
    #[test]
    fn test_derive_keypair() {
        // Create a seed
        let seed = [0u8; 64];
        // Derive a keypair from the seed
        let keypair = derive(&seed).unwrap();
        // Assert the length of the public and secret keys
        assert_eq!(keypair.public.len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret.len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test for public key extraction
    #[test]
    fn test_public_key_extraction() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Extract public key from the secret key
        let extracted_pk = public(&keypair.secret);
        // Assert equality of the extracted public key and the original public key
        assert_eq!(extracted_pk, keypair.public);
    }

    // Test for handling of invalid inputs
    #[test]
    fn test_invalid_input_handling() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Define invalid public key, ciphertext, and secret key
        let invalid_pk = [0u8; KYBER_PUBLIC_KEY_BYTES - 1];
        let invalid_ct = [0u8; KYBER_CIPHERTEXT_BYTES - 1];
        let invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES - 1];

        // Assert error handling for encapsulation with invalid public key
        assert!(encapsulate(&invalid_pk, &mut rng).is_err());
        // Assert error handling for decapsulation with invalid ciphertext and secret key
        assert!(decapsulate(&invalid_ct, &keypair.secret).is_err());
        assert!(decapsulate(&invalid_ct, &invalid_secret_key).is_err());
        // Assert error handling for keypair derivation with invalid secret key
        assert!(derive(&invalid_secret_key).is_err());

        // Define invalid seed
        let invalid_seed = [0u8; 63];
        // Assert error handling for keypair derivation with invalid seed
        assert!(derive(&invalid_seed).is_err());
    }
}
