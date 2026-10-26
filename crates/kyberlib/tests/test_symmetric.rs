// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    // Import necessary items
    use kyberlib::{
        symmetric::{hash_g, hash_h, kdf, prf},
        KYBER_SHARED_SECRET_BYTES,
    };

    // Test the hash_h function
    #[test]
    fn test_hash_h() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; 32];

        // Call the hash_h function
        hash_h(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 32]);
    }

    // Test the hash_g function
    #[test]
    fn test_hash_g() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; 64];

        // Call the hash_g function
        hash_g(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 64]);
    }

    // Test the xof_absorb and xof_squeezeblocks functions.
    // `kyber_shake128_*` are only compiled in non-90s mode (SHAKE-based KEM);
    // 90s mode swaps the XOF for AES256-CTR and exposes a different surface.
    #[cfg(not(feature = "90s"))]
    #[test]
    fn test_xof_absorb_squeeze() {
        use kyberlib::params::KYBER_SYM_BYTES;
        use kyberlib::symmetric::KeccakState;
        use kyberlib::symmetric::{
            kyber_shake128_absorb, kyber_shake128_squeezeblocks,
        };

        const SHAKE128_RATE: usize = 168;

        let mut state = KeccakState::new();
        let input = [1u8; KYBER_SYM_BYTES];
        let x = 1;
        let y = 2;
        let mut out = [0u8; SHAKE128_RATE];

        // Absorb input data into the Kyber-specific SHAKE128 state
        kyber_shake128_absorb(&mut state, &input, x, y);
        let nblocks = out.len() / SHAKE128_RATE;
        kyber_shake128_squeezeblocks(&mut out, nblocks, &mut state);
        let outlen = out.len();
        let mut idx = 0;
        for &byte in out.iter() {
            assert_ne!(byte, 0);
            idx += 1;
        }
        assert_eq!(idx, outlen);
    }

    // Test the prf function
    #[test]
    fn test_prf() {
        use kyberlib::params::KYBER_SYM_BYTES;
        let mut key = [0u8; KYBER_SYM_BYTES];
        key[..8].copy_from_slice(b"test key");
        let nonce = 42;
        let mut out = [0u8; 64];
        let outbytes = out.len();

        // Call the prf function
        prf(&mut out, outbytes, &key, nonce);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 64]);
    }

    // Test the kdf function
    #[test]
    fn test_kdf() {
        let input = b"test input";
        let inlen = input.len();
        let mut out = [0u8; KYBER_SHARED_SECRET_BYTES];

        // Call the kdf function
        kdf(&mut out, input, inlen);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; KYBER_SHARED_SECRET_BYTES]);
    }

    #[cfg(not(feature = "90s"))]
    #[test]
    fn test_kyber_shake128_absorb_squeeze() {
        use kyberlib::params::KYBER_SYM_BYTES;
        use kyberlib::symmetric::KeccakState;
        use kyberlib::symmetric::{
            kyber_shake128_absorb, kyber_shake128_squeezeblocks,
        };

        const SHAKE128_RATE: usize = 168;

        let mut state = KeccakState::new();
        let input = [1u8; KYBER_SYM_BYTES];
        let x = 1;
        let y = 2;
        let mut out = [0u8; SHAKE128_RATE];

        // Absorb input data into the Kyber-specific SHAKE128 state
        kyber_shake128_absorb(&mut state, &input, x, y);

        // Squeeze Kyber-specific SHAKE128 data into output
        kyber_shake128_squeezeblocks(&mut out, 1, &mut state);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; SHAKE128_RATE]);
    }

    // Regression: `KeccakState` derived `Debug`, which printed the
    // 25 sponge lanes. After absorbing a key or seed they are derived
    // from that input, so they are redacted like other secrets.
    #[cfg(not(feature = "90s"))]
    #[test]
    fn test_keccak_state_debug_redacts_lanes() {
        use kyberlib::params::KYBER_SYM_BYTES;
        use kyberlib::symmetric::{kyber_shake128_absorb, KeccakState};

        let mut state = KeccakState::new();
        kyber_shake128_absorb(
            &mut state,
            &[0xA5; KYBER_SYM_BYTES],
            1,
            2,
        );
        assert_ne!(state.s, [0u64; 25]);

        let compact = format!("{state:?}");
        assert_eq!(
            compact,
            format!(
                "KeccakState {{ s: [REDACTED 200 bytes], pos: {} }}",
                state.pos
            )
        );
        let pretty = format!("{state:#?}");
        for lane in state.s.iter().filter(|lane| **lane > 9) {
            let lane = lane.to_string();
            assert!(!compact.contains(&lane), "{compact}");
            assert!(!pretty.contains(&lane), "{pretty}");
        }
    }

    // Regression: in 90s mode `XofState` is `Aes256CtrCtx`, which
    // derived `Debug` and printed the expanded AES-256 key schedule.
    #[cfg(all(feature = "90s", not(feature = "90s-fixslice")))]
    #[test]
    fn test_aes256ctr_state_debug_redacts_key_schedule() {
        use kyberlib::symmetric::{xof_absorb, XofState};

        let mut state = XofState::new();
        xof_absorb(&mut state, &[0xA5; 32], 1, 2);
        assert_ne!(state.sk_exp, [0u64; 120]);

        let compact = format!("{state:?}");
        assert_eq!(
            compact,
            "Aes256CtrCtx { sk_exp: [REDACTED 960 bytes], \
             ivw: [64 bytes; not secret] }"
        );
        let pretty = format!("{state:#?}");
        for word in state.sk_exp.iter().filter(|word| **word > 9) {
            let word = word.to_string();
            assert!(!compact.contains(&word), "{compact}");
            assert!(!pretty.contains(&word), "{pretty}");
        }
    }

    #[cfg(not(feature = "90s"))]
    #[test]
    fn test_shake256_prf() {
        use kyberlib::params::KYBER_SYM_BYTES;
        use kyberlib::symmetric::shake256_prf;

        let mut key = [0u8; KYBER_SYM_BYTES];
        key.copy_from_slice(&[0u8; KYBER_SYM_BYTES]);
        let nonce = 42;
        let mut out = [0u8; 32]; // Output length of SHAKE256 is 32 bytes
        let outlen = out.len();

        // Call the SHAKE256 PRF function
        shake256_prf(&mut out, outlen, &key, nonce);

        // Assert that the output is not all zeros
        assert_ne!(out, [0u8; 32]);
    }
}
