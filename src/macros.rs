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
/// Example
///
/// ```rust
/// use kyberlib::loggers::LogFormat;  
/// use kyberlib::kyberlib_info;
/// use kyberlib::loggers::Log;
/// use kyberlib::loggers::LogLevel;
/// 
/// let log = kyberlib_info!(  
///    "session123",
///    "2023-01-04T21:00:00",
///    "app",
///    "Message logged",    
///    LogFormat::CLF
/// );
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
/// Example  
/// 
/// ```rust
/// use kyberlib::loggers::LogFormat;  
/// use kyberlib::kyberlib_error;
/// use kyberlib::loggers::Log;
/// use kyberlib::loggers::LogLevel;
///  
/// let error_log = kyberlib_error!(
///     "session123",  
///     "2023-01-04T21:00:00",
///     "app",
///     "Connection failed",
///     LogFormat::CLF
/// );
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
/// Example
///
/// ```
/// use kyberlib::loggers::{LogLevel};
/// use kyberlib::kyberlib_debug;
/// use kyberlib::loggers::Log;
/// use kyberlib::loggers::LogFormat;
///
/// let log = kyberlib_debug!(
///     "session123",
///     "2023-01-04T21:00:00",  
///     "app",
///     "Message logged",
///     LogFormat::CLF
/// );
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
/// Example 
///
/// ```rust  
/// use kyberlib::loggers::{LogLevel, LogFormat};
/// use kyberlib::kyberlib_log;
///   
/// let log = kyberlib_log!(    
///    "session123",  
///    "2023-01-04T21:00:00",
///    "app",
///    "Message logged",   
///    LogFormat::CLF  
/// );
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
