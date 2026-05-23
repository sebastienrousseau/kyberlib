//! Smoke tests for the kyberlib-hybrid public surface.

#[test]
#[cfg(feature = "x25519")]
fn x25519_mlkem768_constants_are_spec() {
    use kyberlib_hybrid::{Hybrid, X25519MlKem768};
    // draft-ietf-tls-ecdhe-mlkem-04 codepoint + share sizes.
    assert_eq!(<X25519MlKem768 as Hybrid>::TLS_CODEPOINT, 0x11EC);
    assert_eq!(<X25519MlKem768 as Hybrid>::CLIENT_SHARE_LEN, 1216);
    assert_eq!(<X25519MlKem768 as Hybrid>::SERVER_SHARE_LEN, 1120);
    assert_eq!(<X25519MlKem768 as Hybrid>::SHARED_SECRET_LEN, 64);
}
