// Copyright © 2026 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Hazardous APIs (feature `hazmat`).
//!
//! Everything here is outside FIPS 203 and has not been analysed by any
//! standards body. Use it only if you have checked that its properties
//! fit your protocol; prefer the typed ML-KEM API ([`crate::KemCore`]) or
//! an established protocol (TLS 1.3 hybrids in `kyberlib-hybrid`, HPKE).

pub mod kex;
