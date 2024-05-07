// Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    use kyberlib::wasm::Kex;
    use kyberlib::{decapsulate, encapsulate, keypair, params::*};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_keypair() {
        let mut rng = rand::rngs::OsRng {};
        let result = keypair(&mut rng);
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_encapsulate() {
        let mut rng = rand::rngs::OsRng {};
        let pk = vec![0u8; KYBER_PUBLIC_KEY_BYTES].into_boxed_slice();
        let result = encapsulate(&pk, &mut rng);
        assert!(result.is_err()); // Invalid input sizes

        let keypair_result = keypair(&mut rng);
        assert!(keypair_result.is_ok());

        let result = encapsulate(&pk, &mut rng);
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_decapsulate() {
        let ct = vec![0u8; KYBER_CIPHERTEXT_BYTES].into_boxed_slice();
        let sk = vec![0u8; KYBER_SECRET_KEY_BYTES].into_boxed_slice();
        let result = decapsulate(&ct, &sk);
        assert!(result.is_err()); // Invalid input sizes

        let keypair_result = keypair(&mut rand::rngs::OsRng {});
        assert!(keypair_result.is_ok());

        let keys = keypair_result.unwrap();
        let result = encapsulate(&keys.public, &mut rand::rngs::OsRng {});
        assert!(result.is_ok());

        let result = decapsulate(&ct, &keys.secret);
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_kex_new() {
        let pk = vec![0u8; KYBER_PUBLIC_KEY_BYTES].into_boxed_slice();
        let result = Kex::new(pk);
        assert!(result.ciphertext().len() == KYBER_CIPHERTEXT_BYTES);
        assert!(result.sharedSecret().len() == KYBER_SHARED_SECRET_BYTES);
    }
}
