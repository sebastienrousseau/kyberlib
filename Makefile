# kyberlib developer Makefile.
#
# Targets mirror the noyalib convention (see CONTRIBUTING.md). All targets
# operate on the full workspace unless otherwise noted.

CARGO        ?= cargo
RUSTFLAGS    ?=
RUSTDOCFLAGS ?= -D warnings -D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links -D rustdoc::invalid_codeblock_attributes -D rustdoc::invalid_html_tags -D rustdoc::bare_urls

# ----------------------------------------------------------------- defaults
.DEFAULT_GOAL := check
.PHONY: help check build test clippy fmt fmt-check doc \
        deny vet machete msrv no-std vendor coverage \
        fuzz fuzz-smoke acvp examples bench miri \
        sbom cbom clean ci

help: ## Show this help.
	@grep -hE '^[a-zA-Z_.-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------- build
check: ## cargo check across the workspace (default features).
	$(CARGO) check --workspace

build: ## cargo build across the workspace (default features).
	$(CARGO) build --workspace

# --------------------------------------------------------------- testing
test: ## cargo test --workspace --all-features.
	$(CARGO) test --workspace --all-features

test-no-std: ## Build the safe core with no default features.
	$(CARGO) check -p kyberlib --lib --no-default-features --features kyber768

# --------------------------------------------------------------- quality
clippy: ## clippy --all-targets -D warnings across the workspace.
	$(CARGO) clippy --workspace --all-features --all-targets -- -D warnings

fmt: ## Apply rustfmt across the workspace.
	$(CARGO) fmt --all

fmt-check: ## Verify rustfmt across the workspace (no writes).
	$(CARGO) fmt --all -- --check

doc: ## Strict rustdoc build.
	RUSTDOCFLAGS="$(RUSTDOCFLAGS)" $(CARGO) doc --no-deps --all-features --workspace

# --------------------------------------------------------------- supply chain
deny: ## cargo deny check (advisories, bans, licenses, sources).
	$(CARGO) deny --all-features check

vet: ## cargo vet check (audited deps; requires `cargo install cargo-vet`).
	$(CARGO) vet check

machete: ## cargo machete (unused dep detection).
	$(CARGO) machete

# --------------------------------------------------------------- MSRV / no_std
msrv: ## Verify the declared MSRV (Rust 1.74) builds across feature combos.
	$(CARGO) +1.74.0 check --workspace --all-features
	$(CARGO) +1.74.0 check -p kyberlib --no-default-features --features kyber768

no-std: ## Verify no_std builds for the safe core.
	$(CARGO) check -p kyberlib --lib --no-default-features --features kyber768

# --------------------------------------------------------------- packaging
vendor: ## Air-gapped build simulation: cargo vendor + offline build.
	$(CARGO) vendor --versioned-dirs vendor > /tmp/cargo-vendor.toml.fragment
	@echo "Append /tmp/cargo-vendor.toml.fragment to .cargo/config.toml to use."

# --------------------------------------------------------------- coverage
coverage: ## Run llvm-cov (nightly) and emit lcov.
	NOYALIB_COVERAGE=1 $(CARGO) +nightly llvm-cov --workspace --all-features --lcov --output-path lcov.info

# --------------------------------------------------------------- fuzz
# Requires nightly + cargo-fuzz: `cargo install cargo-fuzz`.
FUZZ_TARGET ?= fuzz_decap

fuzz-smoke: ## 10-second smoke fuzz against $(FUZZ_TARGET) (default: fuzz_decap).
	cd fuzz && cargo +nightly fuzz run $(FUZZ_TARGET) -- -runs=0 -max_total_time=10

fuzz: ## Run cargo fuzz against TARGET (default fuzz_decap, set RUNS for cap).
	cd fuzz && cargo +nightly fuzz run $(FUZZ_TARGET) $(if $(RUNS),-- -runs=$(RUNS),)

fuzz-list: ## List available fuzz targets.
	cd fuzz && cargo +nightly fuzz list

# --------------------------------------------------------------- miri
# Requires nightly + miri: `rustup +nightly component add miri`.
miri: ## Run the focused Miri subset.
	bash scripts/miri.sh

miri-full: ## Run the full Miri suite (slow — many minutes).
	bash scripts/miri.sh full

# --------------------------------------------------------------- dudect (constant-time analysis)
dudect: ## Run statistical constant-time analysis on decapsulate (scaffolded — phase 2b gate).
	bash scripts/dudect.sh

# --------------------------------------------------------------- ACVP (phase 2)
acvp: ## Run NIST ACVP ML-KEM-768 vectors (60 cases). Reports pass / fail per group.
	RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' \
	  $(CARGO) test -p kyberlib --test test_acvp -- --nocapture

acvp-refresh: ## Re-download NIST ACVP vectors and verify SHA-256.
	bash scripts/acvp-refresh.sh

# --------------------------------------------------------------- examples / bench
examples: ## Run all examples once each.
	$(CARGO) build --examples --workspace
	$(CARGO) run --example kem
	$(CARGO) run --example uake
	$(CARGO) run --example ake

bench: ## Run criterion benchmarks (sequential).
	$(CARGO) bench --workspace

# --------------------------------------------------------------- SBOM / CBOM (phase 4)
sbom: ## Generate a CycloneDX 1.5 SBOM (requires `cargo install cargo-cyclonedx`).
	$(CARGO) cyclonedx --spec-version 1.5 --override-filename sbom

cbom: ## Generate a CycloneDX 1.6 CBOM with cryptoProperties (requires cargo-cyclonedx + jq).
	bash scripts/cbom.sh

# --------------------------------------------------------------- hygiene
clean: ## cargo clean.
	$(CARGO) clean

# --------------------------------------------------------------- CI parity
ci: fmt-check clippy doc test deny machete ## Run the local CI superset.
