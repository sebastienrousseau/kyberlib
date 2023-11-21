<!-- markdownlint-disable MD033 MD041 -->

<img
src="https://kura.pro/kyberlib/images/logos/kyberlib.webp"
alt="kyberlib's logo"
height="261"
width="261"
align="right"
/>

<!-- markdownlint-enable MD033 MD041 -->

# kyberlib

A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography.

<!-- markdownlint-disable MD033 MD041 -->
<center>
<!-- markdownlint-enable MD033 MD041 -->

[![Made With Rust][made-with-rust-badge]][05]
[![Crates.io][crates-badge]][07]
[![Lib.rs][libs-badge]][09]
[![Docs.rs][docs-badge]][08]
[![License][license-badge]][02]

• [Website][00]
• [Documentation][08]
• [Report Bug][03]
• [Request Feature][03]
• [Contributing Guidelines][04]

<!-- markdownlint-disable MD033 MD041 -->
</center>
<!-- markdownlint-enable MD033 MD041 -->

![divider][divider]

## Overview 📖

KyberLib is a robust Rust library designed for CRYSTALS-Kyber Post-Quantum Cryptography, offering strong security guarantees. This library is compatible with `no_std`, making it suitable for embedded devices and avoids memory allocations. Additionally, it contains reference implementations with no unsafe code and provides an optimized AVX2 version by default on x86_64 platforms. You can also compile it to WebAssembly (WASM) using wasm-bindgen.

## Features ✨

### Core Features

- **`no_std` compatible**: No dependence on the Rust standard library
- **Avoid allocations**: Uses stack-based data structures only
- **Configurable**: Features to enable different parameter sets
- **Optimised x86_64**: Uses assembly for performance-critical code, including an optimised AVX2 version by default.
- **Safe code**: Reference implementations have no `unsafe` blocks
- **WebAssembly Support**: Can be compiled to WASM using wasm-bindgen.

### Advanced Features

- **Allocation-free Guarantee**: KyberLib guarantees all its core cryptography operations are free of heap allocations.
- **Assembly Optimizations**: The x86_64 assembly implementations use AVX2 instructions for high performance.
- **Security**: KyberLib contains no unsafe code in its public API surface.

## Functionality 📚

- **Key Generation**: Create public/private key pairs
- **Encapsulation**: Encapsulate a shared secret with a public key
- **Decapsulation**: Decapsulate a shared secret with a private key
- **Key Exchange**: Perform authenticated key exchanges

See [Documentation][08] for full API details.

## Getting Started 🚀

It takes just a few minutes to get up and running with `kyberlib`.

### Requirements

The minimum supported Rust toolchain version is currently Rust
**1.56.0** or later (stable).

### Installation

To install `kyberlib`, you need to have the Rust toolchain installed on
your machine. You can install the Rust toolchain by following the
instructions on the [Rust website][13].

Once you have the Rust toolchain installed, you can install `kyberlib`
using the following command:

```shell
cargo install kyberlib
```

## Usage 📖

To use the `kyberlib` library in your project, add the following to your
`Cargo.toml` file:

```toml
[dependencies]
kyberlib = "0.0.2"
```

Add the following to your `main.rs` file:

```rust
extern crate kyberlib;
use kyberlib::*;
```

then you can use the functions in your application code.

### Examples

To get started with `kyberlib`, you can use the examples provided in the
`examples` directory of the project.

To run the examples, clone the repository and run the following command
in your terminal from the project root directory.

#### Example 1: Implements an authenticated key exchange protocol

Alice and Bob exchange public keys to derive a shared secret in a way that authenticates each party.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example ake
```

#### Example 2: Demonstrates key encapsulation and decapsulation

Alice generates a keypair. Bob encapsulates a secret using Alice's public key. Alice decapsulates the secret using her private key. This allows secure communication.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example kem
```

#### Example 3: Implements an unauthenticated key exchange protocol

Alice and Bob exchange public information to derive a shared secret without authenticating each other. Provides confidentiality but not authentication.

Run the following command in your terminal from the project root directory.

```shell
cargo run --example uake
```

### Platform support

`kyberlib` is supported and tested on the following platforms:

### Tier 1 platforms 🏆

| | Operating System | Target | Description |
| --- | --- | --- | --- |
| ✅ | Linux   | aarch64-unknown-linux-gnu | 64-bit Linux systems on ARM architecture |
| ✅ | Windows | i686-pc-windows-gnu | 32-bit Windows systems using the GNU toolchain |
| ✅ | Windows | i686-pc-windows-msvc | 32-bit Windows systems using the Microsoft Visual C toolchain |
| ✅ | Linux   | i686-unknown-linux-gnu | 32-bit Linux systems (kernel 3.2+, glibc 2.17+) |
| ✅ | macOS   | x86_64-apple-darwin | 64-bit macOS systems (10.7 Lion or later) |
| ✅ | Windows | x86_64-pc-windows-gnu | 64-bit Windows systems using the GNU toolchain |
| ✅ | Windows | x86_64-pc-windows-msvc | 64-bit Windows systems using the Microsoft Visual C toolchain |
| ✅ | Linux   | x86_64-unknown-linux-gnu | 64-bit Linux systems (kernel 2.6.32+, glibc 2.11+) |

### Tier 2 platforms 🥈

| | Operating System | Target | Description |
| --- | --- | --- | --- |
| ✅ | Linux   | aarch64-apple-darwin | 64-bit macOS on Apple Silicon |
| ✅ | Windows | aarch64-pc-windows-msvc | 64-bit Windows on ARM architecture using the Microsoft Visual C toolchain |
| ✅ | Linux   | aarch64-unknown-linux-musl | 64-bit Linux on ARM architecture with musl libc |
| ✅ | Linux   | arm-unknown-linux-gnueabi | ARMv6 Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | arm-unknown-linux-gnueabihf | ARMv7 Linux systems, hardfloat (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | armv7-unknown-linux-gnueabihf | ARMv7 Linux systems, hardfloat (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | powerpc-unknown-linux-gnu | PowerPC Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | powerpc64-unknown-linux-gnu | PowerPC64 Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | powerpc64le-unknown-linux-gnu | PowerPC64le Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | riscv64gc-unknown-linux-gnu | RISC-V Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | s390x-unknown-linux-gnu | s390x Linux systems (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | x86_64-unknown-freebsd | 64-bit FreeBSD systems on x86-64 architecture |
| ✅ | Linux   | x86_64-unknown-linux-musl | 64-bit Linux systems (kernel 2.6.32+, musl libc) |

The [GitHub Actions][10] shows the platforms in which the `kyberlib`
library tests are run.

### Documentation

**Info:** Please check out our [website][00] for more information. You can find our documentation on [docs.rs][08], [lib.rs][09] and
[crates.io][07].

## Semantic Versioning Policy 🚥

For transparency into our release cycle and in striving to maintain
backward compatibility, `kyberlib` follows [semantic versioning][06].

## License 📝

The project is licensed under the terms of MIT.

## Contribution 🤝

We welcome all people who want to contribute. Please see the
[contributing instructions][04] for more information.

Contributions in any form (issues, pull requests, etc.) to this project
must adhere to the [Rust's Code of Conduct][11].

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

## Acknowledgements 💙

A big thank you to all the awesome contributors of [kyberlib][05] for their
help and support.

This repo is a fork of the innovative Rust implementation of the Kyber
post-quantum KEM from [Argyle-Software/kyber][01]. We are deeply grateful for
the inspiration and contribution of the original project, which has provided a
solid foundation for our work and study. Thank you! You can find the original
repo [here][01].

A special thank you goes to the [Rust Reddit][12] community for
providing a lot of useful suggestions on how to improve this project.

[00]: https://kyberlib.com/
[01]: https://github.com/Argyle-Software/kyber
[02]: http://opensource.org/licenses/MIT
[03]: https://github.com/sebastienrousseau/kyberlib/kyberlib/issues
[04]: https://github.com/sebastienrousseau/kyberlib/kyberlib/blob/main/CONTRIBUTING.md
[05]: https://github.com/sebastienrousseau/kyberlib/kyberlib/graphs/contributors
[06]: http://semver.org/
[07]: https://crates.io/crates/kyberlib
[08]: https://docs.rs/kyberlib
[09]: https://lib.rs/crates/kyberlib
[10]: https://github.com/sebastienrousseau/kyberlib/kyberlib/actions
[11]: https://www.rust-lang.org/policies/code-of-conduct
[12]: https://www.reddit.com/r/rust/
[13]: https://www.rust-lang.org/learn/get-started

[crates-badge]: https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge 'Crates.io badge'
[divider]: https://kura.pro/common/images/elements/divider.svg "divider"
[docs-badge]: https://img.shields.io/docsrs/kyberlib.svg?style=for-the-badge 'Docs.rs badge'
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.1-orange.svg?style=for-the-badge 'Lib.rs badge'
[license-badge]: https://img.shields.io/crates/l/kyberlib.svg?style=for-the-badge 'License badge'
[made-with-rust-badge]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust badge'
