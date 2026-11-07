// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The ML-KEM-512 and ML-KEM-1024 key and ciphertext wrappers, generated
//! by one macro. Split out of `ml_kem.rs` to keep that file within the
//! size ceiling; the types are re-exported from `crate::ml_kem`.

use super::{MlKem1024, MlKem512};
use crate::error::KyberLibError;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------- ML-KEM-512 + 1024 typed wrappers

macro_rules! sized_wrapper_types {
    ($p:ident, $ek:ident, $dk:ident, $ct:ident, $pk_bytes:expr, $sk_bytes:expr, $ct_bytes:expr) => {
        /// Public encapsulation key.
        #[derive(Clone, Copy, Eq, PartialEq)]
        #[non_exhaustive]
        pub struct $ek(pub(crate) [u8; $pk_bytes]);

        impl $ek {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $pk_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $pk_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                let mut buf = [0u8; $pk_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes.
            pub fn as_bytes(&self) -> &[u8; $pk_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $ek {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($ek))
                    .field(&format_args!(
                        "[{} bytes; not secret]",
                        $pk_bytes
                    ))
                    .finish()
            }
        }

        /// Secret decapsulation key. Zeroized on drop.
        #[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
        #[non_exhaustive]
        pub struct $dk(pub(crate) [u8; $sk_bytes]);

        impl $dk {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $sk_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length
            /// and the FIPS 203 §7.3 hash check (the stored `H(ek)`
            /// must match the embedded encapsulation key).
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch;
            /// [`KyberLibError::InvalidKey`] if the hash check fails.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $sk_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                if !crate::input_check::dk_hash_check::<$p>(bytes) {
                    return Err(KyberLibError::InvalidKey);
                }
                let mut buf = [0u8; $sk_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes. Sparingly — the secret state is
            /// exposed.
            pub fn as_bytes(&self) -> &[u8; $sk_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $dk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(
                    stringify!($dk),
                    "([REDACTED ",
                    stringify!($sk_bytes),
                    " bytes])"
                ))
            }
        }

        /// Ciphertext.
        #[derive(Clone, Copy, Eq, PartialEq)]
        #[non_exhaustive]
        pub struct $ct(pub(crate) [u8; $ct_bytes]);

        impl $ct {
            /// Construct from raw bytes.
            pub fn from_bytes(bytes: [u8; $ct_bytes]) -> Self {
                Self(bytes)
            }
            /// Construct from a borrowed slice, validating the length.
            ///
            /// # Errors
            ///
            /// [`KyberLibError::InvalidLength`] on length mismatch.
            pub fn try_from_slice(
                bytes: &[u8],
            ) -> Result<Self, KyberLibError> {
                if bytes.len() != $ct_bytes {
                    return Err(KyberLibError::InvalidLength);
                }
                let mut buf = [0u8; $ct_bytes];
                buf.copy_from_slice(bytes);
                Ok(Self(buf))
            }
            /// Borrow as raw bytes.
            pub fn as_bytes(&self) -> &[u8; $ct_bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $ct {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($ct))
                    .field(&format_args!(
                        "[{} bytes; opaque]",
                        $ct_bytes
                    ))
                    .finish()
            }
        }
    };
}

sized_wrapper_types!(
    MlKem512,
    MlKem512EncapKey,
    MlKem512DecapKey,
    MlKem512Ciphertext,
    800,
    1632,
    768
);
sized_wrapper_types!(
    MlKem1024,
    MlKem1024EncapKey,
    MlKem1024DecapKey,
    MlKem1024Ciphertext,
    1568,
    3168,
    1568
);
