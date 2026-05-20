# Release process

Checklist for maintainers cutting a new kyberlib release. Walks
through everything from version bump to crates.io publish + signed
GitHub Release.

## Cadence

* **Patch (0.0.x)** — bug fixes, doc improvements, dependency
  bumps, internal refactors that don't change the public API.
* **Minor (0.x.0)** — new features, breaking API changes (in 0.x
  Cargo conventions, minor bumps may break — explicitly call them
  out in CHANGELOG).
* **Major (x.0.0)** — reserved for the post-1.0 era. Currently N/A.

## Pre-flight

1. **Verify the milestone is empty.**
   `gh issue list --milestone vX.Y.Z --state open` should return zero.
   If not, either close the issues or move them to the next milestone.

2. **Refresh ACVP vectors** (annual or on NIST update).
   `cargo xtask acvp-refresh` (or `bash scripts/acvp-refresh.sh`).
   The harness must run 180 / 180 cases green:
   `RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' cargo test -p kyberlib --test test_acvp`.

3. **Run the full security gauntlet** on a quiescent baremetal host
   (CI's shared runners are too noisy for dudect):
   ```sh
   cargo xtask kyberslash       # ADR 0003 regression guard
   cargo xtask miri full        # incl. big-endian sweep, 30-60 min
   cargo xtask dudect full      # 200k samples per CT bench
   ```
   All three must exit clean.

4. **Refresh the CBOM**.
   `cargo xtask cbom` → emits `target/cbom.cdx.json`. Diff against
   the previous release's CBOM to check for unexpected algorithm
   additions.

5. **Tighten `Cargo.lock`** to current minor versions:
   `cargo update --workspace` then `cargo test --workspace --locked`
   to confirm nothing broke.

## Version bump

1. **Pick the version.** Workspace inherits via `version.workspace
   = true`. Bump in exactly one place:

   ```toml
   # Cargo.toml at workspace root
   [workspace.package]
   version = "0.0.7"   # ← bump here
   ```

   Every member crate (`kyberlib`, `kyberlib-asm`, `kyberlib-hybrid`,
   `kyberlib-pkcs8`, `kyberlib-wasm`) inherits.

2. **Update path-dep version pins.** The three satellites
   (`kyberlib-hybrid`, `kyberlib-pkcs8`, `kyberlib-wasm`) declare
   `kyberlib = { path = "../kyberlib", version = "0.0.7", ... }`.
   Update the `version` field in each manifest to match.

3. **Update `html_root_url`** in `crates/kyberlib/src/lib.rs`'s
   `#![doc(html_root_url = "https://docs.rs/kyberlib")]` if your
   convention pins it per-version (default is unversioned — keep
   as-is).

4. **Refresh `CHANGELOG.md`.** Move `## [Unreleased]` content under
   a new `## [0.0.7] - YYYY-MM-DD` heading. Add a new empty
   `## [Unreleased]` section above it.

5. **Refresh `README.md`** install instructions if the version
   number appears in the install snippet.

## Pre-publish dry-run

```sh
# Verify cargo package builds cleanly for the published crate.
cargo package -p kyberlib --no-verify --allow-dirty

# Tarball size sanity check (should be <1 MiB).
ls -lh target/package/kyberlib-*.crate

# Smoke-test the release pipeline locally without uploading.
gh workflow run release.yml -f dry_run=true
```

The `release.yml` workflow's `dry_run` mode runs every step except
the `cargo publish` and the `gh release create`. SLSA L3 provenance,
cosign keyless signing, and CBOM generation are all exercised.

## Tag + publish

1. **Commit + push** the version bump + CHANGELOG. PR review per the
   project's branch-protection rules.

2. **Tag from `main` after merge:**

   ```sh
   git checkout main && git pull
   git tag -s v0.0.7 -m "Release v0.0.7"
   git push origin v0.0.7
   ```

   The `-s` flag SSH-signs the tag (relies on the contributor's
   `gpg.format=ssh` config).

3. **CI takes over.** `.github/workflows/release.yml` runs on the
   tag and:
   - Validates the tag matches `[workspace.package].version`.
   - Runs the full CI superset (fmt + clippy + test on stable +
     doc + cargo-deny).
   - Generates the CBOM via `bash scripts/cbom.sh`.
   - Generates SBOM via `cargo cyclonedx`.
   - Computes SHA-256 + SHA-512 of every artefact.
   - Attaches SLSA L3 build provenance (Rekor transparency log).
   - Cosign keyless signs the `.crate` blob (Fulcio + Rekor).
   - Publishes to crates.io (workspace order: `kyberlib` then
     `kyberlib-wasm`).
   - Creates a draft GitHub Release with every artefact attached.

4. **Publish the GitHub Release draft.** Manually flip the draft to
   "Latest" once the release notes look right.

## Verification recipe for downstream consumers

Document this in the GitHub Release notes:

```sh
# Verify SLSA L3 provenance:
gh attestation verify --owner sebastienrousseau kyberlib-0.0.7.crate

# Verify cosign signature:
cosign verify-blob \
    --certificate-identity-regexp '^https://github\.com/sebastienrousseau/kyberlib/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --bundle kyberlib-0.0.7.crate.cosign-bundle.json \
    kyberlib-0.0.7.crate
```

## Rollback

If a release goes out with a critical bug:

1. **`cargo yank --version 0.0.7 -p kyberlib`** marks the version
   unavailable to new resolvers without breaking existing
   lockfiles.
2. Open an issue tagged `release-blocker` with the symptom.
3. Cut a patch (0.0.8) following this same process — yanked
   versions stay in the registry for forensic purposes.

`cargo yank` is reversible (`--undo`). For permanent removal,
contact the crates.io team — but yanking is the standard remedy.

## Post-release

- [ ] Move closed issues out of the milestone.
- [ ] Open the next milestone.
- [ ] Update PLAN.md's status (flip 📋 → ✅ for newly-landed work,
      add new 📋 entries for the next milestone's scope).
- [ ] Announce: GitHub Discussions, /r/rust, security@rust-lang.org
      mailing list (for CT-relevant releases).
