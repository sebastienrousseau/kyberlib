// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! NIST ACVP ML-KEM conformance harness.
//!
//! Loads `tests/acvp/{keyGen,encapDecap}-{prompt,expected}.json` (the
//! NIST ACVP authoritative test vectors for FIPS 203) and runs each
//! test case against kyberlib's deterministic-seed entry points.
//!
//! ## Running
//!
//! The deterministic-seed surface is gated on the
//! `KYBER_SECURITY_PARAMETERat` cfg (the same gate the legacy
//! pq-crystals KAT harness in `tests/test_kat.rs` uses):
//!
//! ```sh
//! RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' \
//!   cargo test -p kyberlib --test test_acvp -- --nocapture
//! ```
//!
//! or via the workspace `Makefile`:
//!
//! ```sh
//! make acvp
//! ```
//!
//! ## What this harness measures
//!
//! As of Phase 3g of #130b, the harness exercises **ALL THREE**
//! parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024) in a single
//! build via the generic FIPS 203 pipeline (`kem_keypair_generic` etc.
//! exposed via `kyberlib::__testing__`). Coverage:
//!
//!   ML-KEM-512:  25 keyGen + 25 encap + 10 decap = 60 vectors
//!   ML-KEM-768:  25 keyGen + 25 encap + 10 decap = 60 vectors
//!   ML-KEM-1024: 25 keyGen + 25 encap + 10 decap = 60 vectors
//!                                                  =========
//!   Total: 180 NIST ACVP vectors, all 180 pass.
//!
//! Breakdown by ACVP test type:
//!
//!   - keyGen        (75 cases — 25 per parameter set)
//!   - encapsulation (75 cases — 25 per parameter set)
//!   - decapsulation (30 cases — 10 per parameter set)
//!
//! Pre-Phase-3g (before commit 9261088…eabbc6d), the harness skipped
//! ML-KEM-512 and ML-KEM-1024 because kyberlib's reference backend
//! was cfg-gated to a single parameter set. The const-generic
//! refactor lifts that limitation and the harness now drives every
//! NIST vector through the matching generic monomorphization.
//!
//! ## Failure mode
//!
//! Each group reports `passed / total`. On the first failure inside a
//! group the harness prints the offending `tcId`, expected output,
//! and observed output (truncated to 32 hex chars). The aggregate
//! result is asserted at the end of each `#[test]` so an `expectedᐧ
//! results.json` mismatch turns into a `cargo test` failure.

#![cfg(KYBER_SECURITY_PARAMETERat)]

use kyberlib::__testing__::{
    kem_dec_generic, kem_enc_generic, kem_keypair_generic,
};
use kyberlib::{MlKem1024, MlKem512, MlKem768, MlKemParams};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Which FIPS 203 parameter set a test case is exercising.
#[derive(Clone, Copy)]
enum ParamSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

fn parse_set(s: &str) -> Option<ParamSet> {
    match s {
        "ML-KEM-512" => Some(ParamSet::MlKem512),
        "ML-KEM-768" => Some(ParamSet::MlKem768),
        "ML-KEM-1024" => Some(ParamSet::MlKem1024),
        _ => None,
    }
}

fn pk_len(p: ParamSet) -> usize {
    match p {
        ParamSet::MlKem512 => {
            <MlKem512 as MlKemParams>::PUBLIC_KEY_BYTES
        }
        ParamSet::MlKem768 => {
            <MlKem768 as MlKemParams>::PUBLIC_KEY_BYTES
        }
        ParamSet::MlKem1024 => {
            <MlKem1024 as MlKemParams>::PUBLIC_KEY_BYTES
        }
    }
}

fn sk_len(p: ParamSet) -> usize {
    match p {
        ParamSet::MlKem512 => {
            <MlKem512 as MlKemParams>::SECRET_KEY_BYTES
        }
        ParamSet::MlKem768 => {
            <MlKem768 as MlKemParams>::SECRET_KEY_BYTES
        }
        ParamSet::MlKem1024 => {
            <MlKem1024 as MlKemParams>::SECRET_KEY_BYTES
        }
    }
}

fn ct_len(p: ParamSet) -> usize {
    match p {
        ParamSet::MlKem512 => {
            <MlKem512 as MlKemParams>::CIPHERTEXT_BYTES
        }
        ParamSet::MlKem768 => {
            <MlKem768 as MlKemParams>::CIPHERTEXT_BYTES
        }
        ParamSet::MlKem1024 => {
            <MlKem1024 as MlKemParams>::CIPHERTEXT_BYTES
        }
    }
}

/// Dispatch a keygen call to the right generic monomorphization.
fn run_keygen(
    p: ParamSet,
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut rand::rngs::ThreadRng,
    seed: (&[u8], &[u8]),
) -> Result<(), kyberlib::KyberLibError> {
    match p {
        ParamSet::MlKem512 => {
            kem_keypair_generic::<MlKem512, _>(pk, sk, rng, Some(seed))
        }
        ParamSet::MlKem768 => {
            kem_keypair_generic::<MlKem768, _>(pk, sk, rng, Some(seed))
        }
        ParamSet::MlKem1024 => {
            kem_keypair_generic::<MlKem1024, _>(pk, sk, rng, Some(seed))
        }
    }
}

/// Dispatch an encap call to the right generic monomorphization.
fn run_encap(
    p: ParamSet,
    ct: &mut [u8],
    ss: &mut [u8],
    ek: &[u8],
    rng: &mut rand::rngs::ThreadRng,
    seed: &[u8],
) -> Result<(), kyberlib::KyberLibError> {
    match p {
        ParamSet::MlKem512 => {
            kem_enc_generic::<MlKem512, _>(ct, ss, ek, rng, Some(seed))
        }
        ParamSet::MlKem768 => {
            kem_enc_generic::<MlKem768, _>(ct, ss, ek, rng, Some(seed))
        }
        ParamSet::MlKem1024 => {
            kem_enc_generic::<MlKem1024, _>(ct, ss, ek, rng, Some(seed))
        }
    }
}

/// Dispatch a decap call to the right generic monomorphization.
fn run_decap(p: ParamSet, ss: &mut [u8], ct: &[u8], dk: &[u8]) {
    match p {
        ParamSet::MlKem512 => {
            kem_dec_generic::<MlKem512>(ss, ct, dk);
        }
        ParamSet::MlKem768 => {
            kem_dec_generic::<MlKem768>(ss, ct, dk);
        }
        ParamSet::MlKem1024 => {
            kem_dec_generic::<MlKem1024>(ss, ct, dk);
        }
    }
}

// -------------------------------------------------------------------------- JSON schema

#[derive(Deserialize)]
struct AcvpFile<G> {
    #[serde(rename = "testGroups")]
    test_groups: Vec<G>,
}

// --- keyGen --------------------------------------------------------------

#[derive(Deserialize)]
struct KgPromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<KgPromptCase>,
}

#[derive(Deserialize)]
struct KgPromptCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    d: String,
    z: String,
}

#[derive(Deserialize)]
struct KgExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<KgExpectedCase>,
}

#[derive(Deserialize)]
struct KgExpectedCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    ek: String,
    dk: String,
}

// --- encapDecap ----------------------------------------------------------

#[derive(Deserialize)]
struct EdPromptGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    function: String,
    tests: Vec<EdPromptCase>,
}

#[derive(Deserialize)]
struct EdPromptCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    // Encapsulation prompts: ek + m.
    #[serde(default)]
    ek: Option<String>,
    #[serde(default)]
    m: Option<String>,
    // Decapsulation prompts: c + dk.
    #[serde(default)]
    c: Option<String>,
    #[serde(default)]
    dk: Option<String>,
}

#[derive(Deserialize)]
struct EdExpectedGroup {
    #[serde(rename = "tgId")]
    tg_id: u32,
    tests: Vec<EdExpectedCase>,
}

#[derive(Deserialize)]
struct EdExpectedCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    // Encapsulation expected: c + k. Decapsulation expected: k.
    #[serde(default)]
    c: Option<String>,
    #[serde(default)]
    k: Option<String>,
}

// -------------------------------------------------------------------------- helpers

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acvp")
}

fn load_json<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = vectors_dir().join(name);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .unwrap_or_else(|_| panic!("invalid hex at {i}: {s:?}"))
        })
        .collect()
}

fn truncate(b: &[u8]) -> String {
    let n = b.len().min(16);
    let mut s = String::new();
    for byte in &b[..n] {
        s.push_str(&format!("{byte:02X}"));
    }
    if b.len() > n {
        s.push_str("…");
    }
    s
}

/// One PASS/FAIL per `tcId`, plus the first-failure diagnostic.
struct GroupReport {
    group: String,
    passed: u32,
    total: u32,
    first_failure: Option<String>,
}

impl GroupReport {
    fn new(group: impl Into<String>) -> Self {
        Self {
            group: group.into(),
            passed: 0,
            total: 0,
            first_failure: None,
        }
    }
    fn pass(&mut self) {
        self.passed += 1;
        self.total += 1;
    }
    fn fail(&mut self, msg: String) {
        self.total += 1;
        if self.first_failure.is_none() {
            self.first_failure = Some(msg);
        }
    }
    fn print(&self) {
        println!(
            "  {:50}  {:>3}/{:<3}  {}",
            self.group,
            self.passed,
            self.total,
            if self.passed == self.total {
                "OK"
            } else {
                "FAIL"
            },
        );
        if let Some(msg) = &self.first_failure {
            for line in msg.lines() {
                println!("      {line}");
            }
        }
    }
    fn ok(&self) -> bool {
        self.passed == self.total
    }
}

// -------------------------------------------------------------------------- harness: keyGen

#[test]
fn acvp_ml_kem_keygen() {
    let prompt: AcvpFile<KgPromptGroup> =
        load_json("keyGen-prompt.json");
    let expected: AcvpFile<KgExpectedGroup> =
        load_json("keyGen-expected.json");

    let mut report_512 = GroupReport::new("ML-KEM-512 keyGen");
    let mut report_768 = GroupReport::new("ML-KEM-768 keyGen");
    let mut report_1024 = GroupReport::new("ML-KEM-1024 keyGen");
    let mut skipped_groups: Vec<String> = Vec::new();
    let mut rng = rand::thread_rng();

    for pg in &prompt.test_groups {
        let Some(param) = parse_set(&pg.parameter_set) else {
            skipped_groups.push(format!(
                "tgId {} {} (unknown parameter set)",
                pg.tg_id, pg.parameter_set
            ));
            continue;
        };
        let report = match param {
            ParamSet::MlKem512 => &mut report_512,
            ParamSet::MlKem768 => &mut report_768,
            ParamSet::MlKem1024 => &mut report_1024,
        };

        let eg = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == pg.tg_id)
            .expect("expected group with matching tgId");

        for pc in &pg.tests {
            let ec = eg
                .tests
                .iter()
                .find(|c| c.tc_id == pc.tc_id)
                .expect("expected case with matching tcId");

            let d = hex(&pc.d);
            let z = hex(&pc.z);
            assert_eq!(d.len(), 32, "d should be 32 bytes");
            assert_eq!(z.len(), 32, "z should be 32 bytes");

            let mut pk = vec![0u8; pk_len(param)];
            let mut sk = vec![0u8; sk_len(param)];
            let res =
                run_keygen(param, &mut pk, &mut sk, &mut rng, (&d, &z));
            if let Err(e) = res {
                report.fail(format!(
                    "tcId {} keygen returned {:?}",
                    pc.tc_id, e
                ));
                continue;
            }

            let expected_ek = hex(&ec.ek);
            let expected_dk = hex(&ec.dk);
            if pk == expected_ek && sk == expected_dk {
                report.pass();
            } else {
                report.fail(format!(
                    "tcId {} mismatch\n  ek expected {}\n  ek observed {}\n  dk expected {}\n  dk observed {}",
                    pc.tc_id,
                    truncate(&expected_ek),
                    truncate(&pk),
                    truncate(&expected_dk),
                    truncate(&sk),
                ));
            }
        }
    }

    println!("\nACVP keyGen results:");
    report_512.print();
    report_768.print();
    report_1024.print();
    for s in &skipped_groups {
        println!("  SKIPPED: {s}");
    }
    println!();
    let all_ok = report_512.ok() && report_768.ok() && report_1024.ok();
    assert!(all_ok, "ACVP keyGen mismatch — see output above");
}

// -------------------------------------------------------------------------- harness: encap

#[test]
fn acvp_ml_kem_encap() {
    let prompt: AcvpFile<EdPromptGroup> =
        load_json("encapDecap-prompt.json");
    let expected: AcvpFile<EdExpectedGroup> =
        load_json("encapDecap-expected.json");

    let mut report_512 = GroupReport::new("ML-KEM-512 encapsulation");
    let mut report_768 = GroupReport::new("ML-KEM-768 encapsulation");
    let mut report_1024 = GroupReport::new("ML-KEM-1024 encapsulation");
    let mut skipped: Vec<String> = Vec::new();
    let mut rng = rand::thread_rng();

    for pg in &prompt.test_groups {
        if pg.function != "encapsulation" {
            continue;
        }
        let Some(param) = parse_set(&pg.parameter_set) else {
            skipped.push(format!(
                "tgId {} {} (unknown parameter set)",
                pg.tg_id, pg.parameter_set
            ));
            continue;
        };
        let report = match param {
            ParamSet::MlKem512 => &mut report_512,
            ParamSet::MlKem768 => &mut report_768,
            ParamSet::MlKem1024 => &mut report_1024,
        };

        let eg = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == pg.tg_id)
            .expect("expected group with matching tgId");

        for pc in &pg.tests {
            let ec = eg
                .tests
                .iter()
                .find(|c| c.tc_id == pc.tc_id)
                .expect("expected case with matching tcId");

            let ek = hex(pc.ek.as_ref().expect("encap prompt has ek"));
            let m = hex(pc.m.as_ref().expect("encap prompt has m"));
            assert_eq!(
                ek.len(),
                pk_len(param),
                "tcId {} ek length",
                pc.tc_id
            );
            assert_eq!(m.len(), 32, "m should be 32 bytes");

            let mut ct = vec![0u8; ct_len(param)];
            let mut ss = vec![0u8; 32];
            let res =
                run_encap(param, &mut ct, &mut ss, &ek, &mut rng, &m);
            if let Err(e) = res {
                report.fail(format!(
                    "tcId {} encap returned {:?}",
                    pc.tc_id, e
                ));
                continue;
            }

            let expected_c =
                hex(ec.c.as_ref().expect("encap expected c"));
            let expected_k =
                hex(ec.k.as_ref().expect("encap expected k"));
            if ct == expected_c && ss == expected_k {
                report.pass();
            } else {
                report.fail(format!(
                    "tcId {} mismatch\n  c expected {}\n  c observed {}\n  k expected {}\n  k observed {}",
                    pc.tc_id,
                    truncate(&expected_c),
                    truncate(&ct),
                    truncate(&expected_k),
                    truncate(&ss),
                ));
            }
        }
    }

    println!("\nACVP encap results:");
    report_512.print();
    report_768.print();
    report_1024.print();
    for s in &skipped {
        println!("  SKIPPED: {s}");
    }
    println!();
    let all_ok = report_512.ok() && report_768.ok() && report_1024.ok();
    assert!(all_ok, "ACVP encapsulation mismatch — see output above");
}

// -------------------------------------------------------------------------- harness: decap

#[test]
fn acvp_ml_kem_decap() {
    let prompt: AcvpFile<EdPromptGroup> =
        load_json("encapDecap-prompt.json");
    let expected: AcvpFile<EdExpectedGroup> =
        load_json("encapDecap-expected.json");

    let mut report_512 = GroupReport::new("ML-KEM-512 decapsulation");
    let mut report_768 = GroupReport::new("ML-KEM-768 decapsulation");
    let mut report_1024 = GroupReport::new("ML-KEM-1024 decapsulation");
    let mut skipped: Vec<String> = Vec::new();

    for pg in &prompt.test_groups {
        if pg.function != "decapsulation" {
            continue;
        }
        let Some(param) = parse_set(&pg.parameter_set) else {
            skipped.push(format!(
                "tgId {} {} (unknown parameter set)",
                pg.tg_id, pg.parameter_set
            ));
            continue;
        };
        let report = match param {
            ParamSet::MlKem512 => &mut report_512,
            ParamSet::MlKem768 => &mut report_768,
            ParamSet::MlKem1024 => &mut report_1024,
        };

        let eg = expected
            .test_groups
            .iter()
            .find(|g| g.tg_id == pg.tg_id)
            .expect("expected group with matching tgId");

        for pc in &pg.tests {
            let ec = eg
                .tests
                .iter()
                .find(|c| c.tc_id == pc.tc_id)
                .expect("expected case with matching tcId");

            let c = hex(pc.c.as_ref().expect("decap prompt has c"));
            let dk = hex(pc.dk.as_ref().expect("decap prompt has dk"));
            assert_eq!(
                c.len(),
                ct_len(param),
                "tcId {} c length",
                pc.tc_id
            );
            assert_eq!(
                dk.len(),
                sk_len(param),
                "tcId {} dk length",
                pc.tc_id
            );

            let mut observed = vec![0u8; 32];
            run_decap(param, &mut observed, &c, &dk);

            let expected_k =
                hex(ec.k.as_ref().expect("decap expected k"));
            if observed == expected_k {
                report.pass();
            } else {
                report.fail(format!(
                    "tcId {} mismatch\n  k expected {}\n  k observed {}",
                    pc.tc_id,
                    truncate(&expected_k),
                    truncate(&observed),
                ));
            }
        }
    }

    println!("\nACVP decap results:");
    report_512.print();
    report_768.print();
    report_1024.print();
    for s in &skipped {
        println!("  SKIPPED: {s}");
    }
    println!();
    let all_ok = report_512.ok() && report_768.ok() && report_1024.ok();
    assert!(all_ok, "ACVP decapsulation mismatch — see output above");
}
