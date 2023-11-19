#[cfg(test)]
mod tests {
    use kyberlib::aes256::*;

    #[test]
    fn aes256_ctr_ctx_new_should_initialize_fields_to_zero() {
        let ctx = Aes256CtrCtx::new();

        for rkey in ctx.rkeys.iter() {
            assert_eq!(*rkey, __m256i::zero());
        }

        assert_eq!(ctx.n, __m256i::zero());
    }

    #[test]
    fn aesni_encrypt8_should_encrypt_eight_32_byte_data_blocks() {
        let mut ctx = Aes256CtrCtx::new();
        let mut rkeys = [__m256i::zero(); 16];

        // Generate round keys
        key_expansion(&mut rkeys);

        let mut in_data = [0u8; 256];
        let mut out_data = [0u8; 256];

        // Encrypt eight data blocks
        aesni_encrypt8(&mut out_data, &mut ctx.n, &rkeys);

        // Verify that the encrypted data is different from the input data
        for i in 0..256 {
            assert_ne!(in_data[i], out_data[i]);
        }
    }


}
