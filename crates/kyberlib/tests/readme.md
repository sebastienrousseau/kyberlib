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

## Testing

Without any feature flags `cargo test` will run through the key exchange functions and some doctests for the selected security level and mode. Running the Known Answer Tests require deterministic rng buffers from the test vector files. These files are quite large, you will need to generate them yourself. Instructions for building the KAT files are [here](./KAT/readme.md). Otherwise you can run:

```shell
cd KAT
./build_kats.sh
```

Which will clone the C reference repo, generate the KAT files, then rename and put them in the correct folder for testing.

To run the known answer tests you will need to enable `KYBER_SECURITY_PARAMETERat` in `RUSTFLAGS`. To check different Kyber levels or 90's mode you will need to include those flags also. eg:

```bash
RUSTFLAGS=' --cfg KYBER_SECURITY_PARAMETERat' cargo test --features "kyber1024 90s"
```

To run a matrix of all possible features use the helper script from this folder:

```shell
./run_all_tests.sh
```

Set `KAT=1` to also run the known answer tests:

```shell
KAT=1 ./run_all_tests.sh
```

Test files:

* [test_kat.rs](./test_kat.rs) - Legacy CRYSTALS-Kyber Round 3 Known Answer Test harness. Its KAT data files are not in the repository; FIPS 203 conformance is checked by [test_acvp.rs](./test_acvp.rs) (NIST ACVP, 180 vectors).

* [test_kex.rs](./test_kex.rs) - Full `Uake` and `Ake` key exchanges (`kyberlib::hazmat::kex`, needs `--features hazmat`).

* [test_kem.rs](./test_kem.rs) - Random key generation, encapsulation and decapsulation.
