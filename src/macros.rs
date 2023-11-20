// Copyright © 2023 KyberLib. All rights reserved.
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

/// Shorthand macros to create `Log` instances with different log levels.
///
/// # Example
///
/// ```
/// use kyberlib::{kyberlib_info, kyberlib_error, kyberlib_debug};
/// use kyberlib::loggers::{LogLevel, LogFormat};
///
/// let info_log = kyberlib_info!("session_id", "time", "component", "description", LogFormat::Default);
/// ```
#[macro_export]
macro_rules! kyberlib_info {
    ($session_id:expr, $time:expr, $component:expr, $desc:expr, $format:expr) => {
        Log::new(
            $session_id,
            $time,
            LogLevel::INFO,
            $component,
            $desc,
            $format,
        )
    };
}

/// Shorthand macros to create `Log` instances with different log levels.
///
/// # Example
///
/// ```
/// use kyberlib::{kyberlib_info, kyberlib_error, kyberlib_debug};
/// use kyberlib::loggers::{LogLevel, LogFormat};
///
/// let error_log = kyberlib_error!("session_id", "time", "component", "description", LogFormat::Default);
/// ```
#[macro_export]
macro_rules! kyberlib_error {
    ($session_id:expr, $time:expr, $component:expr, $desc:expr, $format:expr) => {
        Log::new(
            $session_id,
            $time,
            LogLevel::ERROR,
            $component,
            $desc,
            $format,
        )
    };
}

/// Shorthand macros to create `Log` instances with different log levels.
///
/// # Example
///
/// ```
/// use kyberlib::{kyberlib_info, kyberlib_error, kyberlib_debug};
/// use kyberlib::loggers::{LogLevel, LogFormat};
///
/// let debug_log = kyberlib_debug!("session_id", "time", "component", "description", LogFormat::Default);
/// ```
#[macro_export]
macro_rules! kyberlib_debug {
    ($session_id:expr, $time:expr, $component:expr, $desc:expr, $format:expr) => {
        Log::new(
            $session_id,
            $time,
            LogLevel::DEBUG,
            $component,
            $desc,
            $format,
        )
    };
}

/// Shorthand macro to create a `Log` with the given log level.
///
/// # Example
///
/// ```
/// use kyberlib::kyberlib_log;
/// use kyberlib::loggers::{LogLevel, LogFormat};
///
/// let log = kyberlib_log!("session_id", "time", "component", "description", LogFormat::Default, LogLevel::INFO);
/// ```
#[macro_export]
macro_rules! kyberlib_log {
    ($session_id:expr, $time:expr, $component:expr, $description:expr, $format:expr) => {{
        use kyberlib::loggers::{Log, LogFormat, LogLevel};

        Log::new(
            $session_id,
            $time,
            LogLevel::INFO,
            $component,
            $description,
            $format,
        )
    }};
}
