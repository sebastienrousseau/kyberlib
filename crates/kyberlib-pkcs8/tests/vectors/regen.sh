#!/usr/bin/env bash
set -euo pipefail
# Regenerates the OpenSSL reference keys used by tests/openssl_interop.rs.
# Needs OpenSSL 3.5 or later (ML-KEM support). Seeds are fixed so the
# output is reproducible: seed = d || z, 64 bytes.
#
#   OPENSSL=/opt/homebrew/opt/openssl@3.5/bin/openssl ./regen.sh
cd "$(dirname "$0")"
OPENSSL="${OPENSSL:-openssl}"
"$OPENSSL" version > openssl-version.txt

seed_for() { # 64 bytes: byte i = (i + n mod 251) mod 256
  python3 -c "import sys;o=int(sys.argv[1])%251;print(bytes((i+o)%256 for i in range(64)).hex())" "$1"
}

for n in 512 768 1024; do
  dir="ml-kem-$n"; mkdir -p "$dir"
  "$OPENSSL" genpkey -algorithm "ML-KEM-$n" -pkeyopt "hexseed:$(seed_for "$n")" \
    -out "$dir/private.pem"
  for fmt in seed-only priv-only seed-priv; do
    "$OPENSSL" pkey -in "$dir/private.pem" -provparam "ml-kem.output_formats=$fmt" \
      -outform DER -out "$dir/$fmt.der"
  done
  "$OPENSSL" pkey -in "$dir/private.pem" -pubout -out "$dir/public.pem"
  "$OPENSSL" pkey -in "$dir/private.pem" -pubout -outform DER -out "$dir/spki.der"
done

# Password-encrypted PKCS#8 (tests/encrypted.rs). Password below is test
# data. PBKDF2-HMAC-SHA256 + AES-256-CBC is OpenSSL's -v2 default; the
# scrypt file uses OpenSSL's scrypt defaults (N=16384, r=8, p=1).
PASS="kyberlib-test-password"
for n in 512 768 1024; do
  dir="ml-kem-$n"
  "$OPENSSL" pkcs8 -topk8 -in "$dir/private.pem" -v2 aes-256-cbc -v2prf hmacWithSHA256 \
    -passout "pass:$PASS" -out "$dir/encrypted-pbkdf2.pem"
  "$OPENSSL" pkcs8 -topk8 -in "$dir/private.pem" -scrypt -v2 aes-256-cbc \
    -passout "pass:$PASS" -out "$dir/encrypted-scrypt.pem"
done
# PBKDF2 with HMAC-SHA-1: must be refused (SHA-1 support is not enabled).
"$OPENSSL" pkcs8 -topk8 -in ml-kem-768/private.pem -v2 aes-256-cbc -v2prf hmacWithSHA1 \
  -passout "pass:$PASS" -out ml-kem-768/encrypted-pbkdf2-sha1.pem
