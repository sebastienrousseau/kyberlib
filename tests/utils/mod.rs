use core::num::NonZeroU32;
use rand_core::{CryptoRng, Error, RngCore};

pub(crate) struct FailingRng(u64);

#[allow(clippy::derivable_impls)]
impl Default for FailingRng {
    fn default() -> Self {
        Self(0)
    }
}

impl RngCore for FailingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, _: &mut [u8]) {}

    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Error> {
        // `Error::new(impl StdError)` requires rand_core's `std` feature.
        // Stay no_std-safe by using a custom-code Error instead.
        let code = NonZeroU32::new(Error::CUSTOM_START + 1).unwrap();
        Err(Error::from(code))
    }
}

impl CryptoRng for FailingRng {}
