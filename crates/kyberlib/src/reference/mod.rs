pub(crate) mod aes256ctr;
pub(crate) mod cbd;
pub(crate) mod fips202;
pub(crate) mod ntt;
pub(crate) mod poly;
pub(crate) mod polyvec;
pub(crate) mod reduce;
pub(crate) mod verify;

#[cfg(not(feature = "hazmat"))]
pub(crate) mod indcpa;

/// IND-CPA primitive layer beneath the CCA-secure KEM. Exposed only with
/// the `hazmat` feature; using this surface directly bypasses the
/// Fujisaki–Okamoto transform and is unsafe for production use.
#[cfg(feature = "hazmat")]
pub mod indcpa;
