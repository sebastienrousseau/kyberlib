// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! SHA3-256 and SHAKE256 (FIPS 202), as ML-KEM itself uses them, for
//! constructions built on ML-KEM such as X-Wing. These are the same
//! Keccak routines the KEM runs, checked by the NIST ACVP vectors
//! through it, in every build: the `90s` and `fips` features change the
//! KEM's primitives, not these.

/// SHA3-256 of `input`.
#[must_use]
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    crate::reference::fips202::sha3_256(
        &mut digest,
        input,
        input.len(),
    );
    digest
}

/// SHAKE256 of `input`, as many bytes as `output` holds.
pub fn shake256(input: &[u8], output: &mut [u8]) {
    crate::reference::fips202::shake256(
        output,
        output.len(),
        input,
        input.len(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `text` (hex) as `N` bytes; no allocation, so the no_std tests
    /// build too.
    fn unhex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
                .unwrap();
        }
        out
    }

    #[test]
    fn known_answers() {
        // FIPS 202 examples (NIST CSRC), empty input.
        assert_eq!(
            sha3_256(b""),
            unhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        assert_eq!(
            out,
            unhex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
        // Lengths that are not a multiple of 8, across blocks (136-byte
        // rate), against Python's hashlib.
        let mut short = [0u8; 33];
        shake256(b"", &mut short);
        assert_eq!(
            short,
            unhex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd7")
        );
        let mut long = [0u8; 300];
        shake256(&[0xa3; 200], &mut long);
        let expected: [u8; 300] = unhex(concat!(
            "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d",
            "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b",
            "1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628",
            "001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317",
            "d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b5",
            "6853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b",
            "61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfaf",
            "a1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e58",
            "9f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea84715",
            "6d277ad0e141c24c7839064c",
        ));
        assert_eq!(long, expected);
        assert_eq!(
            sha3_256(&[0xa3; 200]),
            unhex("79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787")
        );
    }
}
