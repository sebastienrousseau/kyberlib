// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    use kyberlib::rng::randombytes;
    use rand_core::OsRng;

    #[test]
    fn test_randombytes() {
        // Test with a buffer of size 32
        let mut buffer = [0u8; 32];
        let buffer_len = buffer.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes to fill the buffer
        let result = randombytes(&mut buffer, buffer_len, &mut rng);

        // Check if the result is Ok, indicating successful random byte generation
        assert!(result.is_ok());
    }

    #[test]
    fn test_randombytes_success() {
        // Test with a buffer of size 32
        let mut buffer = [0u8; 32];
        let buffer_len = buffer.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes to fill the buffer
        let result = randombytes(&mut buffer, buffer_len, &mut rng);

        // Check if the result is Ok, indicating successful random byte generation
        assert!(result.is_ok());
    }

    #[test]
    fn test_randombytes_small_buffer() {
        // Test with a smaller buffer (8 bytes)
        let mut buffer = [0u8; 8];
        let buffer_len = buffer.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes to fill the buffer
        let result = randombytes(&mut buffer, buffer_len, &mut rng);

        // Check if the result is Ok, indicating successful random byte generation
        assert!(result.is_ok());
        // Check that the buffer length is unchanged
        assert_eq!(buffer.len(), buffer_len);
    }

    #[test]
    fn test_randombytes_large_buffer() {
        // Test with a larger buffer (64 bytes)
        let mut buffer = [0u8; 64];
        let buffer_len = buffer.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes to fill the buffer
        let result = randombytes(&mut buffer, buffer_len, &mut rng);

        // Check if the result is Ok, indicating successful random byte generation
        assert!(result.is_ok());
        // Check that the buffer length is unchanged
        assert_eq!(buffer.len(), buffer_len);
    }

    #[test]
    fn test_randombytes_zero_length_buffer() {
        let mut buffer = [];
        let buffer_len = buffer.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes with a zero-length buffer
        let result = randombytes(&mut buffer, buffer_len, &mut rng);

        // Check if the result is Ok, indicating no error
        assert!(result.is_ok());
        // Check that the buffer length is still zero
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_randombytes_randomness() {
        // Test with a buffer of size 32
        let mut buffer1 = [0u8; 32];
        let mut buffer2 = [0u8; 32];
        let buffer_len = buffer1.len();

        // Use OsRng as the RNG
        let mut rng = OsRng;

        // Call randombytes to fill the first buffer
        let result1 = randombytes(&mut buffer1, buffer_len, &mut rng);

        // Call randombytes to fill the second buffer
        let result2 = randombytes(&mut buffer2, buffer_len, &mut rng);

        // Check if both results are Ok and the buffers are different
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_ne!(&buffer1[..], &buffer2[..]);
    }
}
