// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    /// Tests for feature flags
    mod feature_flags {
        #[test]
        #[cfg(feature = "kyber512")]
        fn test_kyber512_enabled() {
            // Assert that the Kyber512 feature is enabled
            assert!(cfg!(feature = "kyber512"));
        }

        #[test]
        #[cfg(feature = "kyber1024")]
        fn test_kyber1024_enabled() {
            // Assert that the Kyber1024 feature is enabled
            assert!(cfg!(feature = "kyber1024"));
        }

        #[test]
        #[cfg(feature = "90s")]
        fn test_90s_enabled() {
            // Assert that the 90s feature is enabled
            assert!(cfg!(feature = "90s"));
        }

        #[test]
        #[cfg(feature = "avx2")]
        #[cfg(target_arch = "x86_64")]
        fn test_avx2_enabled_x86_64() {
            // Assert that the AVX2 feature is enabled on x86_64 platforms
            assert!(cfg!(feature = "avx2"));
            assert!(cfg!(target_arch = "x86_64"));
        }

        #[test]
        #[cfg(feature = "wasm")]
        fn test_wasm_enabled() {
            // Assert that the WASM feature is enabled
            assert!(cfg!(feature = "wasm"));
        }

        #[test]
        #[cfg(feature = "zeroize")]
        fn test_zeroize_enabled() {
            // Assert that the zeroize feature is enabled
            assert!(cfg!(feature = "zeroize"));
        }

        #[test]
        #[cfg(feature = "std")]
        fn test_std_enabled() {
            // Assert that the std feature is enabled
            assert!(cfg!(feature = "std"));
        }
        #[test]
        #[should_panic(expected = "Only one security level can be specified")]
        #[cfg(all(feature = "kyber512", feature = "kyber1024"))]
        fn test_invalid_feature_combination() {
            // This test should panic with the expected error message
            // when both `kyber512` and `kyber1024` are enabled
        }
    }

    /// Tests for key encapsulation
    mod key_encapsulation {
        #[test]
        fn test_keypair_generation() {
            use kyberlib::keypair;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);
            let result = keypair(&mut rng);
            assert!(result.is_ok());
        }

        #[test]
        fn test_encapsulate_decapsulate() {
            use kyberlib::{decapsulate, encapsulate, keypair};
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);
            let keys = keypair(&mut rng).unwrap();

            let (ciphertext, shared_secret_alice) = encapsulate(&keys.public, &mut rng).unwrap();
            let shared_secret_bob = decapsulate(&ciphertext, &keys.secret).unwrap();

            assert_eq!(shared_secret_alice, shared_secret_bob);
        }
    }

    /// Tests for unilaterally authenticated key exchange
    mod unilaterally_authenticated_key_exchange {
        #[test]
        fn test_uake() {
            use kyberlib::keypair;
            use kyberlib::Uake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Uake::new();
            let mut bob = Uake::new();

            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();

            let server_send = bob
                .server_receive(client_init, &bob_keys.secret, &mut rng)
                .unwrap();

            alice.client_confirm(server_send).unwrap();

            assert_eq!(alice.shared_secret, bob.shared_secret);
        }
    }

    /// Tests for mutually authenticated key exchange
    mod mutually_authenticated_key_exchange {
        #[test]
        fn test_ake() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();

            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();

            assert_eq!(alice.shared_secret, bob.shared_secret);
        }
    }

    /// Tests for error handling
    mod error_handling {
        #[test]
        // Test invalid input errors
        fn test_invalid_input_error() {
            use kyberlib::KyberLibError;
            use kyberlib::{decapsulate, keypair, params::*};
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);
            let keys = keypair(&mut rng).unwrap();

            let invalid_ciphertext = vec![0u8; KYBER_CIPHERTEXT_BYTES - 1];
            let result = decapsulate(&invalid_ciphertext, &keys.secret);
            assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
        }

        #[test]
        // Test valid input with encapsulate and decapsulate functions
        fn test_decapsulate_valid_input() {
            use kyberlib::{decapsulate, encapsulate, keypair};
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);
            let keys = keypair(&mut rng).unwrap();

            let (ciphertext, shared_secret_alice) = encapsulate(&keys.public, &mut rng).unwrap();
            let shared_secret_bob = decapsulate(&ciphertext, &keys.secret).unwrap();

            assert_eq!(shared_secret_alice, shared_secret_bob);
        }

        #[test]
        // Test invalid input public key with encapsulate function
        fn test_encapsulate_invalid_public_key() {
            use kyberlib::encapsulate;
            use kyberlib::KyberLibError;
            use kyberlib::KYBER_PUBLIC_KEY_BYTES;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let invalid_public_key = vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1];
            let result = encapsulate(&invalid_public_key, &mut rng);
            assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
        }
        #[test]
        // Test invalid input secret key with encapsulate function
        fn test_encapsulate_invalid_secret_key() {
            use kyberlib::encapsulate;
            use kyberlib::KyberLibError;
            use kyberlib::KYBER_SECRET_KEY_BYTES;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let invalid_secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES - 1];
            let result = encapsulate(&invalid_secret_key, &mut rng);
            assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
        }
        #[test]
        // Test invalid input secret key with decapsulate function
        fn test_decapsulate_invalid_secret_key() {
            use kyberlib::decapsulate;
            use kyberlib::KyberLibError;
            use kyberlib::KYBER_CIPHERTEXT_BYTES;
            use kyberlib::KYBER_SECRET_KEY_BYTES;

            let invalid_secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES - 1];
            let result = decapsulate(&vec![0u8; KYBER_CIPHERTEXT_BYTES], &invalid_secret_key);
            assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
        }
        #[test]
        // Test invalid input ciphertext with decapsulate function
        fn test_decapsulate_invalid_ciphertext() {
            use kyberlib::decapsulate;
            use kyberlib::params::*;
            use kyberlib::KyberLibError;
            use kyberlib::KYBER_CIPHERTEXT_BYTES;

            let invalid_ciphertext = vec![0u8; KYBER_CIPHERTEXT_BYTES - 1];
            let result = decapsulate(&invalid_ciphertext, &vec![0u8; KYBER_SECRET_KEY_BYTES]);
            assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
        }
        #[test]
        // Test UAKE with invalid public key
        fn test_uake_invalid_public_key() {
            use kyberlib::keypair;
            use kyberlib::Uake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Uake::new();
            let mut bob = Uake::new();

            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &bob_keys.secret, &mut rng)
                .unwrap();

            alice.client_confirm(server_send).unwrap();
        }
        #[test]
        // Test UAKE with invalid secret key
        fn test_uake_invalid_secret_key() {
            use kyberlib::keypair;
            use kyberlib::Uake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Uake::new();
            let mut bob = Uake::new();

            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &bob_keys.secret, &mut rng)
                .unwrap();

            alice.client_confirm(server_send).unwrap();
        }
        #[test]
        // Test AKE with invalid public key
        fn test_ake_invalid_public_key() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();
        }
        #[test]
        // Test AKE with invalid secret key
        fn test_ake_invalid_secret_key() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();
        }
        #[test]
        // Test AKE with invalid shared secret
        fn test_ake_invalid_shared_secret() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();
        }
        #[test]
        // Test AKE with invalid server send
        fn test_ake_invalid_server_send() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();
        }
        #[test]
        // Test AKE with invalid client confirm
        fn test_ake_invalid_client_confirm() {
            use kyberlib::keypair;
            use kyberlib::Ake;
            use rand::rngs::StdRng;
            use rand::SeedableRng;

            let mut rng = StdRng::from_seed([0u8; 32]);

            let mut alice = Ake::new();
            let mut bob = Ake::new();

            let alice_keys = keypair(&mut rng).unwrap();
            let bob_keys = keypair(&mut rng).unwrap();

            let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();
            let server_send = bob
                .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
                .unwrap();

            alice
                .client_confirm(server_send, &alice_keys.secret)
                .unwrap();
        }
    }
    #[test]
    // Test decapsulate with invalid secret key length
    fn test_decapsulate_invalid_ciphertext_length() {
        use kyberlib::KYBER_CIPHERTEXT_BYTES;
        use kyberlib::{decapsulate, keypair, KyberLibError};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([0u8; 32]);
        let keys = keypair(&mut rng).unwrap();

        let invalid_ciphertext = vec![0u8; KYBER_CIPHERTEXT_BYTES - 1];
        let result = decapsulate(&invalid_ciphertext, &keys.secret);
        assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
    }
    #[test]
    // Test decapsulate with invalid secret key length
    fn test_decapsulate_invalid_secret_key_length() {
        use kyberlib::{decapsulate, encapsulate, keypair, KyberLibError, KYBER_SECRET_KEY_BYTES};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([0u8; 32]);
        let keys = keypair(&mut rng).unwrap();
        let (ciphertext, _) = encapsulate(&keys.public, &mut rng).unwrap();

        let invalid_secret_key = vec![0u8; KYBER_SECRET_KEY_BYTES - 1];
        let result = decapsulate(&ciphertext, &invalid_secret_key);
        assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
    }
    #[test]
    // Test encapsulate with invalid secret key length
    fn test_encapsulate_invalid_public_key_length() {
        use kyberlib::{encapsulate, KyberLibError, KYBER_PUBLIC_KEY_BYTES};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([0u8; 32]);

        let invalid_public_key = vec![0u8; KYBER_PUBLIC_KEY_BYTES - 1];
        let result = encapsulate(&invalid_public_key, &mut rng);
        assert_eq!(result.unwrap_err(), KyberLibError::InvalidInput);
    }
    #[test]
    // Test AKE with valid inputs
    fn test_ake_valid_inputs() {
        use kyberlib::{keypair, Ake};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut alice = Ake::new();
        let mut bob = Ake::new();

        let alice_keys = keypair(&mut rng).unwrap();
        let bob_keys = keypair(&mut rng).unwrap();

        let client_init = alice.client_init(&bob_keys.public, &mut rng).unwrap();

        let server_send = bob
            .server_receive(client_init, &alice_keys.public, &bob_keys.secret, &mut rng)
            .unwrap();

        alice
            .client_confirm(server_send, &alice_keys.secret)
            .unwrap();

        assert_eq!(alice.shared_secret, bob.shared_secret);
    }
}
