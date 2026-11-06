// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Checks draft-ietf-tls-ecdhe-mlkem makes mandatory for both peers:
//! the all-zero X25519 shared-secret check (RFC 8446 §7.4.2) and the
//! FIPS 203 §7.2 encapsulation-key check on the server.

#![cfg(feature = "x25519")]

use kyberlib::KyberLibError;
use kyberlib_hybrid::{X25519MlKem768Client, X25519MlKem768Server};
use rand::rngs::OsRng;

/// A low-order X25519 point (the identity, all zeros) yields an
/// all-zero shared secret; the server must refuse it.
#[test]
fn server_rejects_low_order_x25519_share() {
    let (_client, mut share) =
        X25519MlKem768Client::generate(&mut OsRng).unwrap();
    share[1184..].fill(0);
    let result = X25519MlKem768Server::encapsulate(&mut OsRng, &share);
    assert_eq!(result.err(), Some(KyberLibError::InvalidKey));
}

#[test]
fn client_rejects_low_order_x25519_share() {
    let (client, share) =
        X25519MlKem768Client::generate(&mut OsRng).unwrap();
    let (mut server_share, _) =
        X25519MlKem768Server::encapsulate(&mut OsRng, &share).unwrap();
    server_share[1088..].fill(0);
    assert_eq!(
        client.decapsulate(&server_share).err(),
        Some(KyberLibError::InvalidKey)
    );
}

/// FIPS 203 §7.2: an ML-KEM key with an unreduced coefficient is
/// refused before encapsulation.
#[test]
fn server_rejects_unreduced_mlkem_key() {
    let (_client, mut share) =
        X25519MlKem768Client::generate(&mut OsRng).unwrap();
    share[0] = 0xFF;
    share[1] |= 0x0F;
    let result = X25519MlKem768Server::encapsulate(&mut OsRng, &share);
    assert_eq!(result.err(), Some(KyberLibError::InvalidKey));
}
