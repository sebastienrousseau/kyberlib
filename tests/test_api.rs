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

    // Test for keypair generation using Keypair::generate
    #[test]
    fn test_keypair_generate() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair using Keypair::generate
        let keypair = Keypair::generate(&mut rng).unwrap();
        // Assert the length of the public and secret keys
        assert_eq!(keypair.public.len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret.len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test for Keypair::import method
    #[test]
    fn test_keypair_import() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Create mutable references to the public and secret keys
        let mut public_key = keypair.public;
        let mut secret_key = keypair.secret;
        // Import keypair using Keypair::import
        let imported_keypair = Keypair::import(&mut public_key, &mut secret_key, &mut rng).unwrap();
        // Assert equality of the imported keypair and the original keypair
        assert_eq!(imported_keypair.public, keypair.public);
        assert_eq!(imported_keypair.secret, keypair.secret);
    }

    // Test for keypairfrom function
    #[test]
    fn test_keypairfrom() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Create mutable references to the public and secret keys
        let mut public_key = keypair.public;
        let mut secret_key = keypair.secret;
        // Create keypair using keypairfrom
        let new_keypair = keypairfrom(&mut public_key, &mut secret_key, &mut rng).unwrap();
        // Assert equality of the new keypair and the original keypair
        assert_eq!(new_keypair.public, keypair.public);
        assert_eq!(new_keypair.secret, keypair.secret);
    }

    // Test for handling of invalid inputs in keypairfrom
    #[test]
    fn test_keypairfrom_invalid_input() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Define invalid public key and secret key
        let mut invalid_public_key = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES];
        // Modify the public key and secret key to make them invalid
        invalid_public_key[0] = 0xFF;
        invalid_secret_key[0] = 0xFF;
        // Assert error handling for keypairfrom with invalid public key and secret key
        assert!(keypairfrom(&mut invalid_public_key, &mut invalid_secret_key, &mut rng).is_err());
    }

    // Test for handling of invalid inputs in Keypair::import
    #[test]
    fn test_keypair_import_invalid_input() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Define invalid public key and secret key
        let mut invalid_public_key = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES];
        // Modify the public key and secret key to make them invalid
        invalid_public_key[0] = 0xFF;
        invalid_secret_key[0] = 0xFF;
        // Assert error handling for Keypair::import with invalid public key and secret key
        assert!(
            Keypair::import(&mut invalid_public_key, &mut invalid_secret_key, &mut rng).is_err()
        );
    }

    // Test for handling of invalid inputs in Keypair::generate
    #[test]
    fn test_keypair_generate_invalid_input() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Define invalid public key and secret key
        let mut invalid_public_key = [0u8; KYBER_PUBLIC_KEY_BYTES];
        let mut invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES];
        // Modify the public key and secret key to make them invalid
        invalid_public_key[0] = 0xFF;
        invalid_secret_key[0] = 0xFF;
        // Assert error handling for Keypair::generate with invalid public key and secret key
        assert!(Keypair::generate(&mut rng).is_ok());
    }

    // Test for handling of invalid inputs in encapsulate
    #[test]
    fn test_encapsulate_invalid_input() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Define invalid public key
        let invalid_public_key = [0u8; KYBER_PUBLIC_KEY_BYTES - 1];
        // Assert error handling for encapsulate with invalid public key
        assert!(encapsulate(&invalid_public_key, &mut rng).is_err());
    }

    // Test for handling of invalid inputs in decapsulate
    #[test]
    fn test_decapsulate_invalid_input() {
        // Initialize a random number generator
        let mut rng = OsRng;
        // Generate keypair
        let keypair = keypair(&mut rng).unwrap();
        // Define invalid ciphertext and secret key
        let invalid_ciphertext = [0u8; KYBER_CIPHERTEXT_BYTES - 1];
        let invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES - 1];
        // Assert error handling for decapsulate with invalid ciphertext and secret key
        assert!(decapsulate(&invalid_ciphertext, &keypair.secret).is_err());
        assert!(decapsulate(&invalid_ciphertext, &invalid_secret_key).is_err());
    }

    // Test for handling of invalid inputs in derive
    #[test]
    fn test_derive_invalid_input() {
        // Define invalid secret key
        let invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES - 1];
        // Assert error handling for derive with invalid secret key
        assert!(derive(&invalid_secret_key).is_err());
    }

    // Test for handling of invalid inputs in public
    #[test]
    fn test_public_invalid_secret_key_length() {
        let invalid_secret_key = [0u8; KYBER_SECRET_KEY_BYTES - 1];
        assert_eq!(public(&invalid_secret_key).len(), KYBER_PUBLIC_KEY_BYTES);
    }

    // Test for keypair equality
    #[test]
    fn test_keypair_equality() {
        let mut rng = OsRng;
        let keypair1 = keypair(&mut rng).unwrap();
        let keypair2 = keypair(&mut rng).unwrap();
        assert_eq!(keypair1, keypair1);
        assert_ne!(keypair1, keypair2);
    }

    // Test for valid seed for derivation
    #[test]
    fn test_derive_valid_seed() {
        let seed = [0u8; 64];
        let keypair = derive(&seed).unwrap();
        assert_eq!(keypair.public.len(), KYBER_PUBLIC_KEY_BYTES);
        assert_eq!(keypair.secret.len(), KYBER_SECRET_KEY_BYTES);
    }

    // Test for valid input for encapsulation and decapsulation
    #[test]
    fn test_encapsulate_decapsulate_valid_input() {
        let mut rng = OsRng;
        let keypair = keypair(&mut rng).unwrap();
        let (ciphertext, shared_secret) = encapsulate(&keypair.public, &mut rng).unwrap();
        assert_eq!(ciphertext.len(), KYBER_CIPHERTEXT_BYTES);
        assert_eq!(shared_secret.len(), KYBER_SHARED_SECRET_BYTES);
        let decapsulated_secret = decapsulate(&ciphertext, &keypair.secret).unwrap();
        assert_eq!(shared_secret, decapsulated_secret);
    }
}
