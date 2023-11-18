//! # Macros for the `kyberlib` crate.
//!
//! This crate provides the following macros:
//!
//! - `kyberlib`: The main macro for the `kyberlib` crate.
//! - `kyberlib_print`: Prints the arguments to the console.
//! - `kyberlib_vec`: Creates a new vector of the given elements.
//! - `kyberlib_map`: Creates a new map of the given key-value pairs.
//! - `kyberlib_assert`: Checks if the given expression is true.
//! - `kyberlib_min`: Returns the minimum of the given values.
//! - `kyberlib_max`: Returns the maximum of the given values.
//! - `kyberlib_split`: Splits a string into a vector of words.
//! - `kyberlib_join`: Joins a vector of strings into a single string.
//! - `kyberlib_print_vec`: Prints a vector of elements to the console.
//! - `kyberlib_log_info`: Logs information with the specified level, component, and format.
//! - `kyberlib_execute_and_log`: Executes a shell command and logs the start, completion, and any errors.
//!

/// This macro takes any number of arguments and parses them into a
/// Rust value.
#[macro_export]
macro_rules! kyberlib {
    ($($tt:tt)*) => {
        // Parse the arguments into a Rust value.
        $crate::parse!($($tt)*)
    };
}

/// This macro prints the arguments to the console.
#[macro_export]
macro_rules! kyberlib_print {
    ($($arg:tt)*) => {
        println!("{}", format_args!("{}", $($arg)*));
    };
}

/// This macro creates a new vector of the given elements.
#[macro_export]
macro_rules! kyberlib_vec {
    ($($elem:expr),*) => {{
        let mut v = Vec::new();
        $(v.push($elem);)*
        v
    }};
}

/// This macro creates a new map of the given key-value pairs.
#[macro_export]
macro_rules! kyberlib_map {
    ($($key:expr => $value:expr),*) => {{
        use std::collections::HashMap;
        let mut m = HashMap::new();
        $(m.insert($key, $value);)*
        m
    }};
}

/// This macro checks if the given expression is true.
#[macro_export]
macro_rules! kyberlib_assert {
    ($($arg:tt)*) => {
        if !$($arg)* {
            panic!("Assertion failed!");
        }
    };
}

/// This macro returns the minimum of the given values.
#[macro_export]
macro_rules! kyberlib_min {
    ($($x:expr),*) => {{
        let mut min = $($x)*;
        $(if min > $x { min = $x; })*
        min
    }};
}

/// This macro returns the maximum of the given values.
#[macro_export]
macro_rules! kyberlib_max {
    ($($x:expr),*) => {{
        let mut max = $($x)*;
        $(if max < $x { max = $x; })*
        max
    }};
}

/// This macro takes a string and splits it into a vector of words.
#[macro_export]
macro_rules! kyberlib_split {
    ($s:expr) => {{
        let mut v = Vec::new();
        for w in $s.split_whitespace() {
            v.push(w.to_string());
        }
        v
    }};
}

/// This macro takes a vector of strings and joins them together into a
/// single string.
#[macro_export]
macro_rules! kyberlib_join {
    ($($s:expr),*) => {{
        let mut s = String::new();
        $(
            s += &$s;
        )*
        s
    }};
}

/// This macro takes a vector of elements and prints them to the
/// console.
#[macro_export]
macro_rules! kyberlib_print_vec {
    ($($v:expr),*) => {{
        for v in $($v),* {
            println!("{}", v);
        }
    }};
}

// Macro for logging information with various log levels and formats.
#[macro_export]
/// Logs information with the specified level, component, and format.
///
/// # Parameters
///
/// * `$level` - The log level for the message.
/// * `$component` - The component where the log message originates.
/// * `$description` - A description for the log message.
/// * `$format` - The format for the log message.
///
/// # Returns
///
/// This macro returns the created `Log` instance.
macro_rules! kyberlib_log_info {
    ($level:expr, $component:expr, $description:expr, $format:expr) => {{
        use dtt::DateTime;
        use vrd::Random;
        use $crate::loggers::{Log, LogFormat, LogLevel};

        // Get the current date and time in ISO 8601 format.
        let date = DateTime::new();
        let iso = date.iso_8601;

        // Create a new random number generator
        let mut rng = Random::default();
        let session_id = rng.rand().to_string();

        let log = Log::new(
            &session_id,
            &iso,
            $level,
            $component,
            $description,
            $format,
        );
        let _ = log.log();
        log // Return the Log instance
    }};
}
// Macro for executing a shell command and logging the operation.
#[macro_export]
/// Executes a shell command and logs the start, completion, and any errors.
///
/// # Parameters
///
/// * `$command` - The shell command to execute.
/// * `$package` - The name of the package being operated on.
/// * `$operation` - A description of the operation.
/// * `$start_message` - The message to log at the start of the operation.
/// * `$complete_message` - The message to log upon successful completion.
/// * `$error_message` - The message to log in case of an error.
///
/// # Returns
///
/// Returns a `Result<(), anyhow::Error>` to indicate the success or failure of the command execution.
macro_rules! kyberlib_execute_and_log {
    ($command:expr, $package:expr, $operation:expr, $start_message:expr, $complete_message:expr, $error_message:expr) => {{
        use anyhow::{Context, Result as AnyResult};
        use $crate::loggers::{LogFormat, LogLevel};
        use $crate::kyberlib_log_info;

        kyberlib_log_info!(
            LogLevel::INFO,
            $operation,
            $start_message,
            LogFormat::CLF
        );

        $command
            .run()
            .map(|_| ())
            .map_err(|err| {
                kyberlib_log_info!(
                    LogLevel::ERROR,
                    $operation,
                    $error_message,
                    LogFormat::CLF
                );
                err
            })
            .with_context(|| {
                format!(
                    "Failed to execute '{}' for {} on package '{}'",
                    stringify!($command),
                    $operation,
                    $package
                )
            })?;

        kyberlib_log_info!(
            LogLevel::INFO,
            $operation,
            $complete_message,
            LogFormat::CLF
        );
        Ok(())
    }};
}
