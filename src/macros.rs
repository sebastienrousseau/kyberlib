// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # KyberLib Macros
//!
//! A collection of utility macros for various operations like assertions, logging, and executing tasks,
//! specifically designed for `no_std` environments in Rust. These macros provide essential functionalities
//! like logging, assertions, and value comparisons without relying on the standard library.

/// Asserts that a given expression is true. Panics if the assertion fails.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_assert;
/// kyberlib_assert!(1 + 1 == 2);
/// ```
#[macro_export]
macro_rules! kyberlib_assert {
    ($cond:expr $(,)?) => {
        if !$cond {
            // Handle assertion failure in your custom way, e.g., by logging or panic
            // You can define your custom panic handler in a no_std environment.
            panic!("Assertion failed: {}", stringify!($cond));
        }
    };
}

/// Returns the minimum of the given values.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_min;
/// let min = kyberlib_min!(1, 2, 3);
/// assert_eq!(min, 1);
/// ```
#[macro_export]
macro_rules! kyberlib_min {
    ($x:expr $(, $xs:expr)*) => {{
        let mut min = $x;
        $(min = if $xs < min { $xs } else { min };)*
        min
    }};
}

/// Returns the maximum of the given values.
///
/// # Examples
///
/// ```
/// use kyberlib::kyberlib_max;
/// let max = kyberlib_max!(1, 2, 3);
/// assert_eq!(max, 3);
/// ```
#[macro_export]
macro_rules! kyberlib_max {
    ($x:expr $(, $xs:expr)*) => {{
        let mut max = $x;
        $(max = if $xs > max { $xs } else { max };)*
        max
    }};
}
