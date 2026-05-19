<p align="center">
  <img src="https://kura.pro/kyberlib/images/logos/kyberlib.svg" alt="KyberLib logo" width="128" />
</p>

<h1 align="center">KyberLib</h1>

<p align="center">
  <strong>A robust Rust library for CRYSTALS-Kyber post-quantum cryptography.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/kyberlib/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/kyberlib/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/kyberlib"><img src="https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/kyberlib"><img src="https://img.shields.io/badge/docs.rs-kyberlib-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
  <a href="https://codecov.io/gh/sebastienrousseau/kyberlib"><img src="https://img.shields.io/codecov/c/github/sebastienrousseau/kyberlib?style=for-the-badge&logo=codecov" alt="Coverage" /></a>
  <a href="https://lib.rs/crates/kyberlib"><img src="https://img.shields.io/badge/lib.rs-v0.0.7-orange.svg?style=for-the-badge" alt="lib.rs" /></a>
</p>

---

## Install

```bash
cargo add kyberlib
```

Or add to `Cargo.toml`:

```toml
[dependencies]
kyberlib = "0.0.7"
```

You need [Rust](https://rustup.rs/) stable or later. Works on macOS, Linux, and Windows.

---

## Overview

KyberLib implements the CRYSTALS-Kyber key encapsulation mechanism (KEM), a post-quantum cryptographic scheme selected by NIST for standardisation.

- **Key generation** for Kyber512, Kyber768, and Kyber1024
- **Encapsulation/decapsulation** of shared secrets
- **Authenticated key exchange** (AKE and UAKE)
- **Pure safe Rust** — no unsafe code

---

## Features

| | |
| :--- | :--- |
| **CRYSTALS-Kyber** | Full implementation of the Kyber KEM scheme |
| **Key encapsulation** | Generate, encapsulate, and decapsulate shared secrets |
| **Authenticated KE** | Authenticated and unauthenticated key exchange |
| **Parameter sets** | Kyber512, Kyber768, and Kyber1024 security levels |
| **No unsafe code** | Pure safe Rust implementation |

---

## Usage

```rust
use kyberlib::*;

fn main() {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).unwrap();
    let (ciphertext, shared_secret_a) = encapsulate(&keys.public, &mut rng).unwrap();
    let shared_secret_b = decapsulate(&ciphertext, &keys.secret).unwrap();
    assert_eq!(shared_secret_a, shared_secret_b);
}
```

---

## Development

```bash
cargo build        # Build the project
cargo test         # Run all tests
cargo clippy       # Lint with Clippy
cargo fmt          # Format with rustfmt
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, signed commits, and PR guidelines.

---

**THE ARCHITECT** \u1d2b [Sebastien Rousseau](https://sebastienrousseau.com)
**THE ENGINE** \u1d5e [EUXIS](https://euxis.co) \u1d2b Enterprise Unified Execution Intelligence System

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#kyberlib">Back to Top</a></p>