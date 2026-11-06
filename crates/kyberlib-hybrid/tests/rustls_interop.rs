// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Interop with an independent X25519MLKEM768 implementation.
//!
//! The vectors in `vectors/rustls_interop.rs` were captured from real
//! handshakes against rustls 0.23 (aws-lc-rs provider) by
//! `crates/kyberlib-hybrid/interop-gen`. The expected shared secret is
//! always the one rustls derived, so these tests fail if kyberlib's
//! wire layout or secret concatenation drifts from the TLS draft.

#![cfg(feature = "x25519")]

use kyberlib_hybrid::{X25519MlKem768Client, X25519MlKem768Server};
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

fn seed(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte seed")
}

/// kyberlib client, rustls server: the client must parse the server
/// share rustls sent and reach rustls's secret.
#[test]
fn kyberlib_client_matches_rustls_server() {
    for (i, v) in vectors::CLIENT_VECTORS.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed(seed(v.rng_seed));
        let (client, _share) = X25519MlKem768Client::generate(&mut rng)
            .expect("client generate");
        let ss = client
            .decapsulate(&unhex(v.server_share))
            .expect("decapsulate rustls server share");
        assert_eq!(
            ss.as_bytes()[..],
            unhex(v.shared_secret)[..],
            "vector {i}: secret differs from rustls"
        );
    }
}

/// rustls client, kyberlib server: rustls accepted exactly this server
/// share, and the server must reach the secret rustls derived from it.
#[test]
fn kyberlib_server_matches_rustls_client() {
    for (i, v) in vectors::SERVER_VECTORS.iter().enumerate() {
        let mut rng = ChaCha20Rng::from_seed(seed(v.rng_seed));
        let (share, ss) = X25519MlKem768Server::encapsulate(
            &mut rng,
            &unhex(v.client_share),
        )
        .expect("server encapsulate");
        assert_eq!(
            share[..],
            unhex(v.server_share)[..],
            "vector {i}: server share layout differs from what rustls accepted"
        );
        assert_eq!(
            ss.as_bytes()[..],
            unhex(v.shared_secret)[..],
            "vector {i}: secret differs from rustls"
        );
    }
}
