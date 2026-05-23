# kyberlib-asm

> Last Updated: 2026-05-22

> **Placeholder.** The AVX2 / NEON / SVE2 acceleration backends for
> [`kyberlib`](https://crates.io/crates/kyberlib).

This crate is a workspace member skeleton. The actual SIMD code still lives
in `kyberlib`'s `src/avx2/` module — gated behind the `avx2` and `nasm`
Cargo features. The move into this crate is tracked by
[issue #143](https://github.com/sebastienrousseau/kyberlib/issues/143);
the design rationale is documented in
[`doc/adr/0002-asm-quarantine.md`](../../doc/adr/0002-asm-quarantine.md).

Until that move lands, this crate is `publish = false`.
