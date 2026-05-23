//! End-to-end X25519MLKEM768 hybrid KEM round-trip example.
//!
//! Run with: `cargo run -p kyberlib-hybrid --example x25519_mlkem768_round_trip`

#[cfg(feature = "x25519")]
fn main() {
    use kyberlib_hybrid::{X25519MlKem768Client, X25519MlKem768Server};
    let mut rng = rand::thread_rng();

    // Client generates an X25519 + ML-KEM-768 keypair, sends the client_share.
    let (client, client_share) =
        X25519MlKem768Client::generate(&mut rng).expect("client gen");
    println!("client share = {} bytes", client_share.len());

    // Server processes the client_share, encapsulates against it,
    // returns server_share + shared_secret.
    let (server_share, server_ss) =
        X25519MlKem768Server::encapsulate(&mut rng, &client_share)
            .expect("server encap");
    println!("server share = {} bytes", server_share.len());

    // Client decapsulates the server_share into the same shared_secret.
    let client_ss =
        client.decapsulate(&server_share).expect("client decap");
    assert_eq!(client_ss, server_ss, "hybrid KEM round-trip failed");
    println!("shared secret = {} bytes ✓", client_ss.as_bytes().len());
}

#[cfg(not(feature = "x25519"))]
fn main() {
    eprintln!("this example needs `--features x25519`");
}
