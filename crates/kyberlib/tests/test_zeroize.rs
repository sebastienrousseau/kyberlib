// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! What `Zeroize` clears on every secret-holding type, and that each one
//! is `ZeroizeOnDrop`. Written against the derived impls, so the
//! hand-written ones that replace them must clear exactly the same.

use kyberlib::{
    KemCore, Keypair, MlKem1024, MlKem1024DecapKey, MlKem512,
    MlKem512DecapKey, MlKem768, MlKem768DecapKey, SharedSecret,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn every_secret_type_zeroizes_on_drop() {
    zeroize_on_drop::<Keypair>();
    zeroize_on_drop::<SharedSecret>();
    zeroize_on_drop::<MlKem768DecapKey>();
    zeroize_on_drop::<MlKem512DecapKey>();
    zeroize_on_drop::<MlKem1024DecapKey>();
}

#[test]
fn keypair_zeroize_clears_both_keys() {
    let mut keys = Keypair::generate(&mut OsRng).unwrap();
    assert!(keys.public.iter().any(|&b| b != 0));
    keys.zeroize();
    assert!(keys.public.iter().all(|&b| b == 0), "public");
    assert!(keys.expose_secret().iter().all(|&b| b == 0), "secret");
}

#[test]
fn shared_secret_zeroize_clears_it() {
    let (_dk, ek) = MlKem768::generate(&mut OsRng).unwrap();
    let (_ct, mut ss) = ek.encapsulate(&mut OsRng).unwrap();
    assert!(ss.as_bytes().iter().any(|&b| b != 0));
    ss.zeroize();
    assert!(ss.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn decapsulation_keys_zeroize_clear_them() {
    let (mut dk, _) = MlKem768::generate(&mut OsRng).unwrap();
    dk.zeroize();
    assert!(dk.as_bytes().iter().all(|&b| b == 0), "768");
    let (mut dk, _) = MlKem512::generate(&mut OsRng).unwrap();
    dk.zeroize();
    assert!(dk.as_bytes().iter().all(|&b| b == 0), "512");
    let (mut dk, _) = MlKem1024::generate(&mut OsRng).unwrap();
    dk.zeroize();
    assert!(dk.as_bytes().iter().all(|&b| b == 0), "1024");
}

#[cfg(feature = "hazmat")]
#[test]
fn uake_and_ake_zeroize_clear_every_field() {
    use kyberlib::hazmat::kex::{Ake, Uake};
    zeroize_on_drop::<Uake>();
    zeroize_on_drop::<Ake>();
    let bob = Keypair::generate(&mut OsRng).unwrap();

    let mut uake = Uake::new();
    let _ = uake.client_init(&bob.public, &mut OsRng).unwrap();
    uake.shared_secret.fill(7);
    uake.send_b.fill(7);
    uake.zeroize();
    assert!(uake.shared_secret.iter().all(|&b| b == 0), "uake ss");
    assert!(uake.send_a.iter().all(|&b| b == 0), "uake send_a");
    assert!(uake.send_b.iter().all(|&b| b == 0), "uake send_b");
    assert!(uake.temp_key.iter().all(|&b| b == 0), "uake temp_key");
    assert!(uake.eska.iter().all(|&b| b == 0), "uake eska");

    let mut ake = Ake::new();
    let _ = ake.client_init(&bob.public, &mut OsRng).unwrap();
    ake.shared_secret.fill(7);
    ake.send_b.fill(7);
    ake.zeroize();
    assert!(ake.shared_secret.iter().all(|&b| b == 0), "ake ss");
    assert!(ake.send_a.iter().all(|&b| b == 0), "ake send_a");
    assert!(ake.send_b.iter().all(|&b| b == 0), "ake send_b");
    assert!(ake.temp_key.iter().all(|&b| b == 0), "ake temp_key");
    assert!(ake.eska.iter().all(|&b| b == 0), "ake eska");
}
