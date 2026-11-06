// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Input validation for the NIST-curve TLS hybrids: SEC 1 points must
//! be uncompressed, on the curve and not the identity; the server
//! applies the FIPS 203 §7.2 check to the ML-KEM key; lengths are exact.

#![cfg(any(feature = "secp256r1", feature = "secp384r1"))]

use kyberlib::KyberLibError;
use rand::rngs::OsRng;

macro_rules! checks {
    ($feature:literal, $m:ident, $client:ident, $server:ident, $point:expr) => {
        #[cfg(feature = $feature)]
        mod $m {
            use super::*;
            use kyberlib_hybrid::{$client, $server};

            #[test]
            fn round_trip() {
                let (c, share) = $client::generate(&mut OsRng).unwrap();
                let (reply, ss) =
                    $server::encapsulate(&mut OsRng, &share).unwrap();
                assert_eq!(c.decapsulate(&reply).unwrap(), ss);
            }

            #[test]
            fn server_rejects_off_curve_point() {
                let (_, mut share) =
                    $client::generate(&mut OsRng).unwrap();
                share[$point - 1] ^= 1; // perturb Y: no longer on the curve
                assert_eq!(
                    $server::encapsulate(&mut OsRng, &share).err(),
                    Some(KyberLibError::InvalidKey)
                );
            }

            #[test]
            fn server_rejects_compressed_or_identity_encoding() {
                let (_, mut share) =
                    $client::generate(&mut OsRng).unwrap();
                share[0] = 0x02; // compressed tag
                assert_eq!(
                    $server::encapsulate(&mut OsRng, &share).err(),
                    Some(KyberLibError::InvalidKey)
                );
                share[..$point].fill(0); // identity / invalid
                assert_eq!(
                    $server::encapsulate(&mut OsRng, &share).err(),
                    Some(KyberLibError::InvalidKey)
                );
            }

            #[test]
            fn server_rejects_unreduced_mlkem_key() {
                let (_, mut share) =
                    $client::generate(&mut OsRng).unwrap();
                share[$point] = 0xFF;
                share[$point + 1] |= 0x0F;
                assert_eq!(
                    $server::encapsulate(&mut OsRng, &share).err(),
                    Some(KyberLibError::InvalidKey)
                );
            }

            #[test]
            fn client_rejects_bad_point_and_length() {
                let (c, share) = $client::generate(&mut OsRng).unwrap();
                let (mut reply, _) =
                    $server::encapsulate(&mut OsRng, &share).unwrap();
                assert_eq!(
                    $client::generate(&mut OsRng)
                        .unwrap()
                        .0
                        .decapsulate(&reply[1..])
                        .err(),
                    Some(KyberLibError::InvalidInput)
                );
                reply[$point - 1] ^= 1;
                assert_eq!(
                    c.decapsulate(&reply).err(),
                    Some(KyberLibError::InvalidKey)
                );
            }
        }
    };
}

checks!(
    "secp256r1",
    p256,
    SecP256r1MlKem768Client,
    SecP256r1MlKem768Server,
    65
);
checks!(
    "secp384r1",
    p384,
    SecP384r1MlKem1024Client,
    SecP384r1MlKem1024Server,
    97
);
