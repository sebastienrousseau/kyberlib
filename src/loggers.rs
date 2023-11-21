// Copyright © 2023 KyberLib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt;
use core::result::Result as CoreResult;

/// A trait for custom write operations, extending the core `fmt::Write` trait.
/// It provides an additional method for flushing the buffer.
pub trait CustomWrite: fmt::Write {
    /// Flushes the buffer. This should be implemented by types which buffer their output.
    fn custom_flush(&mut self) -> CoreResult<(), CustomError>;
}

/// Represents custom errors for file operations.
/// This struct can be extended to include more detailed error information if required.
#[derive(Debug)]
pub struct CustomError {
    message: &'static str,
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl core::convert::From<&'static str> for CustomError {
    fn from(message: &'static str) -> Self {
        CustomError { message }
    }
}

impl From<core::fmt::Error> for CustomError {
    fn from(_: core::fmt::Error) -> Self {
        CustomError { message: "Formatting error" }
    }
}

/// Enum representing different log formats.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd)]
pub enum LogFormat {
    CLF,
    JSON,
    CEF,
    ELF,
    W3C,
    GELF,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Enum representing different levels of log messages.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd)]
pub enum LogLevel {
    ALL,
    DEBUG,
    DISABLED,
    ERROR,
    FATAL,
    INFO,
    NONE,
    TRACE,
    VERBOSE,
    WARNING,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Represents a log message with various metadata.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Log<'a> {
    pub session_id: &'a str,
    pub time: &'a str,
    pub level: LogLevel,
    pub component: &'a str,
    pub description: &'a str,
    pub format: LogFormat,
}

impl<'a> Log<'a> {
    /// Logs a message to the provided output destination.
    ///
    /// # Arguments
    /// * `file` - The output destination implementing `CustomWrite`.
    ///
    /// # Returns
    /// * `CoreResult<(), CustomError>` - Result of the logging operation.
    pub fn log<T>(&self, file: &mut T) -> CoreResult<(), CustomError>
    where
        T: CustomWrite,
    {
        match self.format {
            LogFormat::CLF => {
                writeln!(
                    file,
                    "SessionID={}\tTimestamp={}\tDescription={}\tLevel={}\tComponent={}\tFormat={}",
                    self.session_id,
                    self.time,
                    self.description,
                    self.level,
                    self.component,
                    self.format
                )?;
            }
            // other format cases...
            _ => return Err("Unsupported log format".into()),
        }

        file.custom_flush()?;
        Ok(())
    }

    /// Creates a new `Log` instance.
    ///
    /// # Arguments
    /// * `session_id` - Session identifier.
    /// * `time` - Timestamp of the log entry.
    /// * `level` - Log level.
    /// * `component` - Component generating the log.
    /// * `description` - Log message description.
    /// * `format` - Format of the log message.
    ///
    /// # Returns
    /// * `Self` - The new `Log` instance.
    pub fn new(
        session_id: &'a str,
        time: &'a str,
        level: LogLevel,
        component: &'a str,
        description: &'a str,
        format: LogFormat,
    ) -> Self {
        Self {
            session_id,
            time,
            level,
            component,
            description,
            format,
        }
    }
}

impl<'a> Default for Log<'a> {
    fn default() -> Self {
        Self {
            session_id: "",
            time: "",
            level: LogLevel::INFO,
            component: "",
            description: "",
            format: LogFormat::CLF,
        }
    }
}

