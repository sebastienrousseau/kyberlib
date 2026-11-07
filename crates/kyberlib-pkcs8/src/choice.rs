// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The RFC 9935 `ML-KEM-*-PrivateKey` CHOICE carried inside the
//! PKCS#8 `privateKey` OCTET STRING:
//!
//! ```text
//! ML-KEM-PrivateKey ::= CHOICE {
//!   seed        [0] OCTET STRING (SIZE (64)),
//!   expandedKey     OCTET STRING (SIZE (DK_LEN)),
//!   both            SEQUENCE {
//!                     seed        OCTET STRING (SIZE (64)),
//!                     expandedKey OCTET STRING (SIZE (DK_LEN)) } }
//! ```
//!
//! The variant is chosen by its tag, never by its length.

use der::asn1::{AnyRef, OctetStringRef};
use der::{Decode, Tag, TagNumber, Tagged};

/// Length of the seed `d ‖ z`.
pub(crate) const SEED_LEN: usize = 64;

/// `[0]` IMPLICIT OCTET STRING: context-specific, primitive, number 0.
const SEED_TAG: Tag = Tag::ContextSpecific {
    constructed: false,
    number: TagNumber(0),
};

/// A decoded private key, borrowing from the DER input.
#[derive(Debug)]
pub(crate) enum Choice<'a> {
    Seed(&'a [u8]),
    Expanded(&'a [u8]),
    Both { seed: &'a [u8], expanded: &'a [u8] },
}

impl<'a> Choice<'a> {
    /// Parses the CHOICE and checks the sizes RFC 9935 fixes. Trailing
    /// bytes after the CHOICE are rejected.
    pub(crate) fn decode(
        bytes: &'a [u8],
        dk_len: usize,
    ) -> der::Result<Self> {
        let any = AnyRef::from_der(bytes)?;
        let choice = Self::from_any(any)?;
        choice.check_sizes(dk_len, any.tag())?;
        Ok(choice)
    }

    fn from_any(any: AnyRef<'a>) -> der::Result<Self> {
        match any.tag() {
            SEED_TAG => Ok(Self::Seed(any.value())),
            Tag::OctetString => Ok(Self::Expanded(any.value())),
            Tag::Sequence => any.sequence(|r| {
                let seed = <&OctetStringRef>::decode(r)?.as_bytes();
                let expanded = <&OctetStringRef>::decode(r)?.as_bytes();
                Ok(Self::Both { seed, expanded })
            }),
            tag => Err(tag.unexpected_error(None).into()),
        }
    }

    fn check_sizes(&self, dk_len: usize, tag: Tag) -> der::Result<()> {
        let ok = match *self {
            Self::Seed(s) => s.len() == SEED_LEN,
            Self::Expanded(e) => e.len() == dk_len,
            Self::Both { seed, expanded } => {
                seed.len() == SEED_LEN && expanded.len() == dk_len
            }
        };
        if ok {
            Ok(())
        } else {
            Err(tag.length_error().into())
        }
    }
}

#[cfg(feature = "alloc")]
pub(crate) use encode::encode;

#[cfg(feature = "alloc")]
mod encode {
    use super::{Choice, SEED_TAG};
    use alloc::vec::Vec;
    use der::asn1::OctetStringRef;
    use der::{Encode, Header, Length, Tag};
    use zeroize::Zeroizing;

    /// Encodes the CHOICE. The buffer is sized up front so the secret
    /// is never left behind in a reallocated block.
    pub(crate) fn encode(
        choice: &Choice<'_>,
    ) -> der::Result<Zeroizing<Vec<u8>>> {
        let mut out =
            Zeroizing::new(Vec::with_capacity(capacity(choice)));
        match *choice {
            Choice::Seed(seed) => encode_seed(seed, &mut out)?,
            Choice::Expanded(dk) => {
                OctetStringRef::new(dk)?.encode_to_vec(&mut out)?;
            }
            Choice::Both { seed, expanded } => {
                encode_both(seed, expanded, &mut out)?;
            }
        }
        Ok(out)
    }

    fn encode_seed(seed: &[u8], out: &mut Vec<u8>) -> der::Result<()> {
        Header::new(SEED_TAG, Length::try_from(seed.len())?)
            .encode_to_vec(out)?;
        out.extend_from_slice(seed);
        Ok(())
    }

    fn encode_both(
        seed: &[u8],
        expanded: &[u8],
        out: &mut Vec<u8>,
    ) -> der::Result<()> {
        let seed = OctetStringRef::new(seed)?;
        let expanded = OctetStringRef::new(expanded)?;
        let len = (seed.encoded_len()? + expanded.encoded_len()?)?;
        Header::new(Tag::Sequence, len).encode_to_vec(out)?;
        seed.encode_to_vec(out)?;
        expanded.encode_to_vec(out)?;
        Ok(())
    }

    /// Payload plus a generous bound on DER headers (at most 3 headers
    /// of at most 4 bytes each).
    fn capacity(choice: &Choice<'_>) -> usize {
        let payload = match *choice {
            Choice::Seed(s) | Choice::Expanded(s) => s.len(),
            Choice::Both { seed, expanded } => {
                seed.len() + expanded.len()
            }
        };
        payload + 12
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DK: usize = 4; // any length works for the parser

    #[test]
    fn decodes_each_variant_by_tag() {
        let mut seed = [0x80, 0x40].to_vec();
        seed.extend([7u8; 64]);
        assert!(matches!(
            Choice::decode(&seed, DK),
            Ok(Choice::Seed(_))
        ));

        let expanded = [0x04, 0x04, 1, 2, 3, 4];
        assert!(matches!(
            Choice::decode(&expanded, DK),
            Ok(Choice::Expanded(e)) if e == [1, 2, 3, 4]
        ));

        let mut both = [0x30, 0x48, 0x04, 0x40].to_vec();
        both.extend([7u8; 64]);
        both.extend([0x04, 0x04, 1, 2, 3, 4]);
        assert!(matches!(
            Choice::decode(&both, DK),
            Ok(Choice::Both { .. })
        ));
    }

    #[test]
    fn rejects_wrong_sizes_tags_and_trailing_data() {
        // seed of 63 bytes
        let mut short = [0x80, 0x3f].to_vec();
        short.extend([7u8; 63]);
        assert!(Choice::decode(&short, DK).is_err());
        // expanded key of the wrong length
        assert!(Choice::decode(&[0x04, 0x03, 1, 2, 3], DK).is_err());
        // [1] instead of [0]
        let mut wrong = [0x81, 0x40].to_vec();
        wrong.extend([7u8; 64]);
        assert!(Choice::decode(&wrong, DK).is_err());
        // trailing byte
        assert!(
            Choice::decode(&[0x04, 0x04, 1, 2, 3, 4, 0], DK).is_err()
        );
        // SEQUENCE with a third element
        let mut extra = [0x30, 0x4b, 0x04, 0x40].to_vec();
        extra.extend([7u8; 64]);
        extra.extend([0x04, 0x04, 1, 2, 3, 4, 0x05, 0x00, 0x00]);
        extra[1] = u8::try_from(extra.len() - 2).unwrap();
        assert!(Choice::decode(&extra, DK).is_err());
    }
}
