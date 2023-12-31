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

## Randbuf Generation

This program generates the deterministic rng output used in the intermediate stages of keypair generation and encoding from KAT seed values. 

`rng.c` and `rng.h` are directly from the NIST submission, `generate_bufs.c` is a stripped down version of `PQCgenKAT_kem.c` to print out the seeded values from `randombytes()` into their respective files. 

These values are then used in place of regular rng output when running the KATs.

To view a diff of `PQCgenKAT_kem.c` and `generate_bufs.c`: 

```shell
diff --color <(curl https://raw.githubusercontent.com/pq-crystals/kyber/master/ref/PQCgenKAT_kem.c) <(curl https://raw.githubusercontent.com/Argyle-Software/kyber/master/tests/rand_bufs/generate_bufs.c)  
```


### Usage

To build and use: 

```shell
cd tests/rand_bufs
make
./generate
mkdir outputs
mv generate_key_pair indcpa_keypair encode outputs/
```

### Original Files

* [rng.c](https://github.com/pq-crystals/kyber/blob/master/ref/rng.c)
* [rng.h](https://github.com/pq-crystals/kyber/blob/master/ref/rng.h)
* [PQCgenKAT_kem.c](https://github.com/pq-crystals/kyber/blob/master/ref/PQCgenKAT_kem.c)


