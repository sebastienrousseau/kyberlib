// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Snapshot regression tests for the public Debug surface.
//
// Why this exists: every secret-bearing type in kyberlib explicitly
// redacts its `Debug` output to prevent accidental secret-key leakage
// into log lines. The redaction is hand-written (NOT
// `#[derive(Debug)]`) precisely because the derive would print the
// raw byte arrays.
//
// If a future refactor accidentally derives `Debug` instead, the
// secrets would leak into every `tracing::debug!` / `dbg!()` call
// — a CVE-class regression that compiles, passes existing tests,
// and ships.
//
// `insta` snapshots the exact Debug output and fails the build on
// any diff. Snapshots live under `tests/snapshots/` and are reviewed
// via `cargo insta review`.
//
// Run with:
//   cargo test --test test_snapshots
//   cargo insta review   # to accept intentional changes

use kyberlib::{
    KemCore, KyberLibError, MlKem768, MlKem768Ciphertext,
    MlKem768DecapKey, MlKem768EncapKey,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn debug_redaction_decap_key() {
    let mut rng = ChaCha20Rng::from_seed([0xA5_u8; 32]);
    let (dk, _) = MlKem768::generate(&mut rng).expect("keygen");
    // Secret-bearing — Debug MUST be redacted.
    insta::assert_snapshot!(format!("{:?}", dk));
}

#[test]
fn debug_redaction_encap_key() {
    let mut rng = ChaCha20Rng::from_seed([0xA5_u8; 32]);
    let (_, ek) = MlKem768::generate(&mut rng).expect("keygen");
    // Public — Debug may show length, but must NOT show the bytes
    // (so swapping a public key for a secret one in logs would still
    // catch the leak via the snapshot diff).
    insta::assert_snapshot!(format!("{:?}", ek));
}

#[test]
fn debug_redaction_shared_secret() {
    let mut rng = ChaCha20Rng::from_seed([0xA5_u8; 32]);
    let (_, ek) = MlKem768::generate(&mut rng).expect("keygen");
    let (_ct, ss) = ek.encapsulate(&mut rng).expect("encap");
    // Highest-sensitivity — `Debug` MUST print "REDACTED" and NOT the bytes.
    insta::assert_snapshot!(format!("{:?}", ss));
}

#[test]
fn debug_ciphertext_is_opaque() {
    let mut rng = ChaCha20Rng::from_seed([0xA5_u8; 32]);
    let (_, ek) = MlKem768::generate(&mut rng).expect("keygen");
    let (ct, _ss) = ek.encapsulate(&mut rng).expect("encap");
    // Public — but still opaque in Debug to keep wire-format bytes
    // out of incidental logs.
    let _: &MlKem768Ciphertext = &ct;
    insta::assert_snapshot!(format!("{:?}", ct));
}

#[test]
fn error_display_messages_stable() {
    // The `Display` impl is part of the public contract — downstream
    // parsers / log scrapers may match on these strings. Snapshot them
    // so a `thiserror` migration doesn't silently change the wording.
    insta::assert_snapshot!(
        "error_invalid_input",
        format!("{}", KyberLibError::InvalidInput)
    );
    insta::assert_snapshot!(
        "error_invalid_key",
        format!("{}", KyberLibError::InvalidKey)
    );
    insta::assert_snapshot!(
        "error_invalid_length",
        format!("{}", KyberLibError::InvalidLength)
    );
    insta::assert_snapshot!(
        "error_decapsulation",
        format!("{}", KyberLibError::Decapsulation)
    );
    insta::assert_snapshot!(
        "error_random_bytes",
        format!("{}", KyberLibError::RandomBytesGeneration)
    );
}

#[test]
fn algorithm_id_table_stable() {
    // The OID + algorithm-id table is referenced by downstream
    // consumers (kyberlib-pkcs8, IETF LAMPS clients). A typo regression
    // could break wire compatibility silently.
    insta::assert_snapshot!(
        "ml_kem_768_algorithm_id",
        <MlKem768 as KemCore>::ALGORITHM_ID
    );
    insta::assert_snapshot!(
        "ml_kem_768_oid",
        <MlKem768 as KemCore>::OID
    );
}

// Unused — referenced only to keep the snapshot tests inside the same
// crate as the types they're checking.
#[allow(dead_code)]
fn _types(_: MlKem768EncapKey, _: MlKem768DecapKey) {}
