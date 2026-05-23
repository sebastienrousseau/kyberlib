// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `xtask` — internal release-pipeline tooling for the kyberlib
//! workspace.
//!
//! Wraps every shell script under `scripts/` in a single Rust
//! binary so contributors only have one entry point to remember and
//! `make` targets can route through `cargo xtask …` without
//! conditional logic.
//!
//! ```text
//! cargo xtask kyberslash               # ADR 0003 secret-/ regression guard
//! cargo xtask miri [focused|full]      # Miri UB detector
//! cargo xtask dudect [quick|full|continuous]  # Welch's t-test CT analysis
//! cargo xtask coverage [--ci]          # cargo-llvm-cov + threshold gate
//! cargo xtask cbom                     # CycloneDX 1.6 CBOM generator
//! cargo xtask acvp-refresh             # refresh NIST ACVP test vectors
//! cargo xtask all-gates                # the per-PR security gauntlet
//! ```
//!
//! Each subcommand is a thin Rust wrapper around the matching
//! `scripts/<name>.sh`. The wrapper:
//!
//! 1. Resolves the repo root via `CARGO_MANIFEST_DIR/../../`.
//! 2. Sets `set -euo pipefail` semantics by checking the child's
//!    exit code and propagating non-zero status.
//! 3. Forwards arguments verbatim to the underlying script so
//!    `cargo xtask dudect continuous` ≡ `bash scripts/dudect.sh
//!    continuous`.
//!
//! The shell scripts remain the canonical implementations. xtask
//! exists to give the workspace a uniform CLI surface and to make
//! the gate composition (`all-gates`) trivial to extend.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Internal release-pipeline tooling for kyberlib",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the KyberSlash regression guard (ADR 0003). Greps for
    /// secret-dependent `/` and `%` against `KYBER_Q`.
    Kyberslash,

    /// Run Miri (UB detector + memory leak / data race detection).
    Miri {
        /// `focused` (default, per-PR ≈10 min) or `full` (release
        /// gate, includes big-endian sweep).
        #[arg(value_name = "MODE", default_value = "focused")]
        mode: String,
    },

    /// Run the dudect constant-time analysis harness (Welch's t-test).
    Dudect {
        /// `quick` (default, 5k samples/class), `full` (200k
        /// samples), or `continuous` (streaming).
        #[arg(value_name = "MODE", default_value = "quick")]
        mode: String,
    },

    /// Run cargo-llvm-cov coverage. `--ci` emits LCOV + Cobertura
    /// + threshold gate; otherwise produces a browser HTML report.
    Coverage {
        /// CI mode: LCOV output + threshold check.
        #[arg(long)]
        ci: bool,
        /// Pass through additional flags to `scripts/coverage.sh`.
        #[arg(trailing_var_arg = true)]
        extra: Vec<String>,
    },

    /// Generate the CycloneDX 1.6 CBOM (Cryptographic Bill of
    /// Materials) for the release pipeline.
    Cbom,

    /// Refresh the NIST ACVP test vectors under `tests/acvp/`.
    AcvpRefresh,

    /// Run the per-PR security gauntlet:
    ///   kyberslash → miri focused → coverage --ci
    AllGates,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = repo_root();
    let ok = match cli.cmd {
        Cmd::Kyberslash => sh(&root, "kyberslash-guard.sh", &[]),
        Cmd::Miri { mode } => sh(&root, "miri.sh", &[&mode]),
        Cmd::Dudect { mode } => sh(&root, "dudect.sh", &[&mode]),
        Cmd::Coverage { ci, extra } => {
            let mut args: Vec<&str> = Vec::new();
            if ci {
                args.push("--ci");
            }
            for a in &extra {
                args.push(a);
            }
            sh(&root, "coverage.sh", &args)
        }
        Cmd::Cbom => sh(&root, "cbom.sh", &[]),
        Cmd::AcvpRefresh => sh(&root, "acvp-refresh.sh", &[]),
        Cmd::AllGates => {
            sh(&root, "kyberslash-guard.sh", &[])
                && sh(&root, "miri.sh", &["focused"])
                && sh(&root, "coverage.sh", &["--ci"])
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Resolve the workspace root from `$CARGO_MANIFEST_DIR`. The
/// xtask crate lives at `<root>/crates/xtask/` so the root is two
/// directories up.
fn repo_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect(
            "xtask crate must be two levels below the workspace root",
        )
}

/// Invoke `bash scripts/<script>` from the workspace root, forwarding
/// extra args. Returns `true` on success.
fn sh(root: &PathBuf, script: &str, args: &[&str]) -> bool {
    let script_path = root.join("scripts").join(script);
    if !script_path.is_file() {
        eprintln!(
            "xtask: missing script {} (looked at {})",
            script,
            script_path.display()
        );
        return false;
    }
    let status = Command::new("bash")
        .arg(&script_path)
        .args(args)
        .current_dir(root)
        .status();
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("xtask: {} exited with {}", script, s);
            false
        }
        Err(e) => {
            eprintln!("xtask: failed to spawn {}: {}", script, e);
            false
        }
    }
}
