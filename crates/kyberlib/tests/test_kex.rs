use kyberlib::*;
mod utils;
use utils::*;

// Kyber struct uake and ake functions
#[test]
fn uake_valid() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    alice.client_confirm(server_send).unwrap();
    assert_eq!(alice.shared_secret, bob.shared_secret);
}

// Corrupted ciphertext sent to bob, 4 bytes modified
#[test]
fn uake_invalid_client_init_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[KYBER_PUBLIC_KEY_BYTES..][..4]
        .copy_from_slice(&[255u8; 4]);
    assert!(bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Corrupted public key sent to bob, detected by Alice
#[test]
fn uake_invalid_client_init_publickey() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[..4].copy_from_slice(&[255u8; 4]);
    let server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    assert!(alice.client_confirm(server_send).is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Corrupted ciphertext sent back to Alice
#[test]
fn uake_invalid_server_send_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    server_send[..4].copy_from_slice(&[255u8; 4]);
    assert!(alice.client_confirm(server_send).is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

// Same tests for AKE

#[test]
fn ake_valid() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng,
        )
        .unwrap();
    alice
        .client_confirm(server_send, &alice_keys.secret)
        .unwrap();
    assert_eq!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_client_init_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[KYBER_PUBLIC_KEY_BYTES..][..4]
        .copy_from_slice(&[255u8; 4]);
    assert!(bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng
        )
        .is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_client_init_publickey() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    client_init[..4].copy_from_slice(&[255u8; 4]);
    let server_send = bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng,
        )
        .unwrap();
    assert!(alice
        .client_confirm(server_send, &alice_keys.secret)
        .is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_server_send_first_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng,
        )
        .unwrap();
    server_send[..4].copy_from_slice(&[255u8; 4]);
    assert!(alice
        .client_confirm(server_send, &alice_keys.secret)
        .is_ok());
    assert_ne!(alice.shared_secret, bob.shared_secret);
}

#[test]
fn ake_invalid_server_send_second_ciphertext() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut server_send = bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng,
        )
        .unwrap();
    server_send[KYBER_CIPHERTEXT_BYTES..][..4]
        .copy_from_slice(&[255u8; 4]);
    // assert!(alice.client_confirm(server_send, &alice_keys.secret).is_err());
}

// Rng function fails on keypair
#[test]
fn ake_uake_failed_randombytes_keypair() {
    let mut rng = FailingRng::default();
    assert_eq!(
        keypair(&mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

// Rng function fails on Alice's client init function
#[test]
fn uake_failed_randombytes_client_init() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        alice.client_init(&bob_keys.public, &mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

// Rng function fails on Bob's server receive function
#[test]
fn uake_failed_randombytes_server_receive() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        bob.server_receive(client_init, &bob_keys.secret, &mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

#[test]
fn ake_failed_randombytes_client_init() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        alice.client_init(&bob_keys.public, &mut rng),
        Err(KyberLibError::RandomBytesGeneration)
    );
}

#[test]
fn ake_failed_randombytes_server_receive() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let mut rng = FailingRng::default();
    assert_eq!(
        bob.server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng
        ),
        Err(KyberLibError::RandomBytesGeneration)
    )
}

// Every decimal number in a Debug rendering. A derived Debug on the
// byte arrays prints each byte as a number, so this catches key bytes
// in both the compact and the pretty form.
fn debug_numbers(rendered: &str) -> Vec<String> {
    rendered
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn byte_window(bytes: &[u8]) -> String {
    let window = format!("{:?}", &bytes[..16]);
    window
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn expected_lengths(init: usize, response: usize) -> Vec<String> {
    [
        KYBER_SHARED_SECRET_BYTES,
        init,
        response,
        KYBER_SHARED_SECRET_BYTES,
        KYBER_SECRET_KEY_BYTES,
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}

// Regression: `Uake` derived `Debug`, which printed the shared secret,
// the ephemeral KDF key and the ephemeral secret key.
#[test]
fn uake_debug_redacts_secrets() {
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let mut bob = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(client_init, &bob_keys.secret, &mut rng)
        .unwrap();
    alice.client_confirm(server_send).unwrap();

    let compact = format!("{alice:?}");
    assert_eq!(
        compact,
        format!(
            "Uake {{ shared_secret: [REDACTED {KYBER_SHARED_SECRET_BYTES} bytes], \
             send_a: [{UAKE_INIT_BYTES} bytes; not secret], \
             send_b: [{UAKE_RESPONSE_BYTES} bytes; not secret], \
             temp_key: [REDACTED {KYBER_SHARED_SECRET_BYTES} bytes], \
             eska: [REDACTED {KYBER_SECRET_KEY_BYTES} bytes] }}"
        )
    );
    for rendered in [compact.clone(), format!("{alice:#?}")] {
        assert_eq!(
            debug_numbers(&rendered),
            expected_lengths(UAKE_INIT_BYTES, UAKE_RESPONSE_BYTES),
            "{rendered}"
        );
    }
    assert!(!compact.contains(&byte_window(&alice.shared_secret)));
    assert!(!compact.contains(&byte_window(&alice.eska)));
}

// Regression: `Ake` derived `Debug` with the same three secrets.
#[test]
fn ake_debug_redacts_secrets() {
    let mut rng = rand::thread_rng();
    let mut alice = Ake::new();
    let mut bob = Ake::new();
    let alice_keys = keypair(&mut rng).unwrap();
    let bob_keys = keypair(&mut rng).unwrap();
    let client_init =
        alice.client_init(&bob_keys.public, &mut rng).unwrap();
    let server_send = bob
        .server_receive(
            client_init,
            &alice_keys.public,
            &bob_keys.secret,
            &mut rng,
        )
        .unwrap();
    alice
        .client_confirm(server_send, &alice_keys.secret)
        .unwrap();

    let compact = format!("{alice:?}");
    assert_eq!(
        compact,
        format!(
            "Ake {{ shared_secret: [REDACTED {KYBER_SHARED_SECRET_BYTES} bytes], \
             send_a: [{AKE_INIT_BYTES} bytes; not secret], \
             send_b: [{AKE_RESPONSE_BYTES} bytes; not secret], \
             temp_key: [REDACTED {KYBER_SHARED_SECRET_BYTES} bytes], \
             eska: [REDACTED {KYBER_SECRET_KEY_BYTES} bytes] }}"
        )
    );
    for rendered in [compact.clone(), format!("{alice:#?}")] {
        assert_eq!(
            debug_numbers(&rendered),
            expected_lengths(AKE_INIT_BYTES, AKE_RESPONSE_BYTES),
            "{rendered}"
        );
    }
    assert!(!compact.contains(&byte_window(&alice.shared_secret)));
    assert!(!compact.contains(&byte_window(&alice.eska)));
}

// `Uake` and `Ake` hold the session key and the ephemeral secret key;
// they implement `Zeroize` (and `ZeroizeOnDrop`) like `Keypair`.
#[test]
fn uake_ake_zeroize_clears_secrets() {
    use zeroize::Zeroize;
    let mut rng = rand::thread_rng();
    let mut alice = Uake::new();
    let bob_keys = keypair(&mut rng).unwrap();
    let _ = alice.client_init(&bob_keys.public, &mut rng).unwrap();
    assert_ne!(alice.eska, [0u8; KYBER_SECRET_KEY_BYTES]);
    alice.zeroize();
    assert_eq!(alice.eska, [0u8; KYBER_SECRET_KEY_BYTES]);
    assert_eq!(alice.temp_key, [0u8; KYBER_SHARED_SECRET_BYTES]);

    let mut ake = Ake::new();
    let _ = ake.client_init(&bob_keys.public, &mut rng).unwrap();
    ake.zeroize();
    assert_eq!(ake.eska, [0u8; KYBER_SECRET_KEY_BYTES]);
    assert_eq!(ake.temp_key, [0u8; KYBER_SHARED_SECRET_BYTES]);
}

// Adding `ZeroizeOnDrop` gives the types a `Drop` impl. Every field is
// a `Copy` byte array, so reading, destructuring and struct-update
// syntax keep working for callers.
#[test]
fn uake_ake_fields_still_destructure() {
    let u = Uake {
        shared_secret: [7u8; KYBER_SHARED_SECRET_BYTES],
        ..Uake::default()
    };
    let Uake { shared_secret, .. } = u;
    assert_eq!(shared_secret, [7u8; KYBER_SHARED_SECRET_BYTES]);
    let a = Ake::default();
    let Ake { send_a, .. } = a;
    assert_eq!(send_a, [0u8; AKE_INIT_BYTES]);
}
