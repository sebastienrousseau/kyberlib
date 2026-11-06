// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interop with an independent implementation of the TLS hybrids.
//!
//! The vectors in `vectors/rustls_interop.rs` were captured against
//! rustls 0.23 (aws-lc-rs provider) by `crates/kyberlib-hybrid/interop-gen`.
//! The expected secret is always the one rustls derived, and for the
//! server direction rustls accepted exactly the recorded server share,
//! so these tests fail if kyberlib's wire layout or secret order drifts
//! from draft-ietf-tls-ecdhe-mlkem. SecP384r1MLKEM1024 is checked
//! against rustls's SECP384R1 and MLKEM1024 groups combined in the
//! draft's layout, as rustls has no such hybrid.

#![cfg(any(
    feature = "x25519",
    feature = "secp256r1",
    feature = "secp384r1"
))]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

struct ClientVector {
    rng_seed: &'static str,
    server_share: &'static str,
    shared_secret: &'static str,
}

struct ServerVector {
    client_share: &'static str,
    rng_seed: &'static str,
    server_share: &'static str,
    shared_secret: &'static str,
}

mod vectors {
    use super::{ClientVector, ServerVector};
    include!("vectors/rustls_interop.rs");
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn rng(s: &str) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(unhex(s).try_into().expect("32-byte seed"))
}

macro_rules! interop_tests {
    ($feature:literal, $module:ident, $client:ident, $server:ident, $cv:ident, $sv:ident) => {
        #[cfg(feature = $feature)]
        mod $module {
            use super::*;
            use kyberlib_hybrid::{$client, $server};

            /// kyberlib client, rustls server.
            #[test]
            fn kyberlib_client_matches_rustls_server() {
                for (i, v) in vectors::$cv.iter().enumerate() {
                    let (client, _) =
                        $client::generate(&mut rng(v.rng_seed))
                            .expect("generate");
                    let ss = client
                        .decapsulate(&unhex(v.server_share))
                        .expect("decapsulate");
                    assert_eq!(
                        ss.as_bytes()[..],
                        unhex(v.shared_secret)[..],
                        "vector {i}: secret"
                    );
                }
            }

            /// rustls client, kyberlib server.
            #[test]
            fn kyberlib_server_matches_rustls_client() {
                for (i, v) in vectors::$sv.iter().enumerate() {
                    let (share, ss) = $server::encapsulate(
                        &mut rng(v.rng_seed),
                        &unhex(v.client_share),
                    )
                    .expect("encapsulate");
                    assert_eq!(
                        share[..],
                        unhex(v.server_share)[..],
                        "vector {i}: server share"
                    );
                    assert_eq!(
                        ss.as_bytes()[..],
                        unhex(v.shared_secret)[..],
                        "vector {i}: secret"
                    );
                }
            }
        }
    };
}

interop_tests!(
    "x25519",
    x25519_mlkem768,
    X25519MlKem768Client,
    X25519MlKem768Server,
    X25519_CLIENT,
    X25519_SERVER
);
interop_tests!(
    "secp256r1",
    secp256r1_mlkem768,
    SecP256r1MlKem768Client,
    SecP256r1MlKem768Server,
    P256_CLIENT,
    P256_SERVER
);
interop_tests!(
    "secp384r1",
    secp384r1_mlkem1024,
    SecP384r1MlKem1024Client,
    SecP384r1MlKem1024Server,
    P384_CLIENT,
    P384_SERVER
);
