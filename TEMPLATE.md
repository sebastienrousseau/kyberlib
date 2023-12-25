<!-- markdownlint-disable MD033 MD041 -->

<img
src="https://kura.pro/kyberlib/images/logos/kyberlib.webp"
alt="kyberlib's logo"
height="199"
width="199"
align="right"
/>

<!-- markdownlint-enable MD033 MD041 -->

# kyberlib

A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography

<!-- markdownlint-disable MD033 MD041 -->
<center>
<!-- markdownlint-enable MD033 MD041 -->

[![Made With Rust][made-with-rust-badge]][5]
[![Crates.io][crates-badge]][7]
[![Lib.rs][libs-badge]][9]
[![Docs.rs][docs-badge]][8]
[![License][license-badge]][2]

• [Website][0]
• [Documentation][8]
• [Report Bug][3]
• [Request Feature][3]
• [Contributing Guidelines][4]

<!-- markdownlint-disable MD033 MD041 -->
</center>
<!-- markdownlint-enable MD033 MD041 -->

![divider][divider]

## Overview 📖

A Robust Rust Library for CRYSTALS-Kyber Post-Quantum Cryptography

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

[0]: https://kyberlib.com/
[2]: http://opensource.org/licenses/MIT
[3]: https://github.com/sebastienrousseau/kyberlib/kyberlib/issues
[4]: https://github.com/sebastienrousseau/kyberlib/kyberlib/blob/main/CONTRIBUTING.md
[5]: https://github.com/sebastienrousseau/kyberlib/kyberlib/graphs/contributors
[7]: https://crates.io/crates/kyberlib
[8]: https://docs.rs/kyberlib
[9]: https://lib.rs/crates/kyberlib

[banner]: https://via.placeholder.com/1500x500.png/000000/FFFFFF?text=kyberlib "kyberlib's banner"
[crates-badge]: https://img.shields.io/crates/v/kyberlib.svg?style=for-the-badge 'Crates.io badge'
[divider]: https://via.placeholder.com/1024x1.png/d8dee4/FFFFFF?text=− "kyberlib's divider"
[docs-badge]: https://img.shields.io/docsrs/kyberlib.svg?style=for-the-badge 'Docs.rs badge'
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.1-orange.svg?style=for-the-badge 'Lib.rs badge'
[license-badge]: https://img.shields.io/crates/l/kyberlib.svg?style=for-the-badge 'License badge'
[made-with-rust-badge]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust badge'

## Changelog 📚
