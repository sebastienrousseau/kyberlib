# v1.0.0 readiness checklist

> Last Updated: 2026-11-07 · Tracking issue:
> [#178](https://github.com/sebastienrousseau/kyberlib/issues/178)

`v1.0.0` is the first release that freezes the public API. Every item
below must be met, and stay met for at least one month, before it is
tagged. Under the repository's versioning rule (`AGENTS.md` §3: `0.0.999`
before `0.1.0`), `v1.0.0` is far off; this list exists so the bar is
written down and checked as the work moves.

Update the **Status** column with evidence (a run, a commit, a report)
whenever an item changes.

| # | Criterion | How it is checked | Status |
|---|-----------|-------------------|---------------------|
| 1 | NIST ACVP vectors pass for ML-KEM-512, -768 and -1024 | `make acvp` (`crates/kyberlib/tests/test_acvp.rs`), in CI | Met: 180/180 |
| 2 | dudect shows no leakage in decapsulation | `cargo xtask dudect full` on a quiet, pinned machine (`docs/BENCHMARKS.md`) | Not met: no full run recorded for the current code |
| 3 | Full Miri sweep clean, including the big-endian target | `.github/workflows/miri-weekly.yml` (`scripts/miri.sh full`) | Met: clean full sweep incl. big-endian on 2026-11-07 ([run 42360566277](https://github.com/sebastienrousseau/kyberlib/actions/runs/42360566277)); must stay clean |
| 4 | Fuzzing soak without crashes for 4 consecutive weeks | A scheduled fuzz job | Not met: only the 10-second per-PR smoke run exists |
| 5 | cargo-vet clean with no exemptions for kyberlib's own dependencies | `cargo vet`; `supply-chain/config.toml` | Not met: exemptions remain for `aes` 0.8.4, `criterion` 0.5.1 and `serde` 1.0.229 |
| 6 | Third-party audit findings resolved and re-verified | Published report under `docs/audits/` | Not met: audit not started (RFP ready: `docs/audits/RFP-v1.0.md`) |
| 7 | Public API frozen for 4 weeks (no SemVer-breaking change merged) | `cargo-semver-checks` in CI, merge history | Not met: breaking changes still planned (#156, #158) |
