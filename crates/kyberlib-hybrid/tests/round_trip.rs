//! End-to-end round-trip tests for the X25519MlKem768 hybrid KEM.
//! Exercises the Debug + PartialEq impls on the SharedSecret and the
//! full client→server→client handshake.

#![cfg(feature = "x25519")]

use kyberlib_hybrid::{X25519MlKem768Client, X25519MlKem768Server};
use rand::rngs::OsRng;

#[test]
fn round_trip_yields_matching_secrets() {
    let mut rng = OsRng;

    let (client, client_share) =
        X25519MlKem768Client::generate(&mut rng).unwrap();

    let (server_share, ss_server) =
        X25519MlKem768Server::encapsulate(&mut rng, &client_share)
            .unwrap();

    let ss_client = client.decapsulate(&server_share).unwrap();

    assert_eq!(
        ss_server, ss_client,
        "client + server must derive identical shared secret"
    );

    let bytes = ss_client.as_bytes();
    assert_eq!(bytes.len(), 64, "shared secret is 64 B per draft-04");
}

#[test]
fn shared_secret_debug_is_redacted() {
    let mut rng = OsRng;
    let (client, client_share) =
        X25519MlKem768Client::generate(&mut rng).unwrap();
    let (server_share, ss) =
        X25519MlKem768Server::encapsulate(&mut rng, &client_share)
            .unwrap();

    let dbg = format!("{:?}", ss);
    assert!(
        dbg.contains("REDACTED"),
        "Debug output for SharedSecret must not reveal the bytes; got: {dbg}"
    );
    assert!(
        dbg.contains("64 bytes"),
        "Debug output should report the byte count"
    );

    // Also exercise client decap path.
    let _ss2 = client.decapsulate(&server_share).unwrap();
}

#[test]
fn shared_secret_partial_eq_is_consistent() {
    let mut rng = OsRng;
    let (client, client_share) =
        X25519MlKem768Client::generate(&mut rng).unwrap();
    let (server_share, ss_a) =
        X25519MlKem768Server::encapsulate(&mut rng, &client_share)
            .unwrap();
    let ss_b = client.decapsulate(&server_share).unwrap();

    assert!(ss_a == ss_b);
    assert!(ss_a == ss_a.clone());
}

#[test]
fn shared_secret_partial_eq_distinguishes_independent_runs() {
    let mut rng = OsRng;

    // First handshake.
    let (client1, share1) =
        X25519MlKem768Client::generate(&mut rng).unwrap();
    let (sshare1, _) =
        X25519MlKem768Server::encapsulate(&mut rng, &share1).unwrap();
    let ss1 = client1.decapsulate(&sshare1).unwrap();

    // Second, independent handshake.
    let (client2, share2) =
        X25519MlKem768Client::generate(&mut rng).unwrap();
    let (sshare2, _) =
        X25519MlKem768Server::encapsulate(&mut rng, &share2).unwrap();
    let ss2 = client2.decapsulate(&sshare2).unwrap();

    assert_ne!(
        ss1.as_bytes(),
        ss2.as_bytes(),
        "independent handshakes must yield different secrets"
    );
    assert!(!(ss1 == ss2));
}

#[test]
fn client_decapsulate_rejects_wrong_length_server_share() {
    use kyberlib::KyberLibError;
    let mut rng = OsRng;
    let (client, _share) =
        X25519MlKem768Client::generate(&mut rng).unwrap();

    let too_short = vec![0u8; 1119];
    let err = client.decapsulate(&too_short).unwrap_err();
    assert!(matches!(err, KyberLibError::InvalidInput));
}

#[test]
fn server_encapsulate_rejects_wrong_length_client_share() {
    use kyberlib::KyberLibError;
    let mut rng = OsRng;
    let bad = vec![0u8; 1215];
    let err =
        X25519MlKem768Server::encapsulate(&mut rng, &bad).unwrap_err();
    assert!(matches!(err, KyberLibError::InvalidInput));
}

#[test]
fn client_debug_is_redacted() {
    let mut rng = OsRng;
    let (client, _) = X25519MlKem768Client::generate(&mut rng).unwrap();
    let dbg = format!("{:?}", client);
    assert!(dbg.contains("REDACTED"));
}
