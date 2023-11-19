// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Standard library imports for formatting and I/O operations.
use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Write as IoWrite},
};

/// Enum representing the different log formats that can be used.
///
/// This enum allows the developer to specify the format in which log messages should be displayed.
///
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd)]
pub enum LogFormat {
    /// The log format is set to the Common Log Format (CLF)
    CLF,
    /// The log format is set to the JSON format
    JSON,
    /// The log format is set to the Common Event Format (CEF)
    CEF,
    /// The log format is set to the Extended Log Format (ELF)
    ELF,
    /// The log format is set to the W3C Extended Log File Format
    W3C,
    /// The log format is set to the Graylog Extended Log Format (GELF)
    GELF,
}

/// Implements Display trait for `LogFormat` enum.
///
/// This allows easy conversion of the log format enums to strings.
impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{self:?}")
    }
}

/// An enumeration of the different levels that a log message can have.
/// Each variant of the enumeration represents a different level of
/// importance.
///
/// # Arguments
///
/// * `ALL` - The log level is set to all.
/// * `DEBUG` - The log level is set to debug.
/// * `DISABLED` - The log level is set to disabled.
/// * `ERROR` - The log level is set to error.
/// * `FATAL` - The log level is set to fatal.
/// * `INFO` - The log level is set to info.
/// * `NONE` - The log level is set to none.
/// * `TRACE` - The log level is set to trace.
/// * `VERBOSE` - The log level is set to verbose.
/// * `WARNING` - The log level is set to warning.
///
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, PartialOrd)]
pub enum LogLevel {
    /// The log level is set to all.
    ALL,
    /// The log level is set to debug.
    DEBUG,
    /// The log level is set to disabled.
    DISABLED,
    /// The log level is set to error.
    ERROR,
    /// The log level is set to fatal.
    FATAL,
    /// The log level is set to info.
    INFO,
    /// The log level is set to none.
    NONE,
    /// The log level is set to trace.
    TRACE,
    /// The log level is set to verbose.
    VERBOSE,
    /// The log level is set to warning.
    WARNING,
}
/// Display trait implementation for `LogLevel`.
///
/// This converts the enum to a string representation.
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Struct representing a log message.
///
/// Contains all the elements that make up a complete log message.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Log {
    /// A string that holds a session ID. The session ID is a unique
    /// identifier for the current session. A random GUID (Globally
    /// Unique Identifier) is generated by default.
    pub session_id: String,
    /// A string that holds the timestamp in ISO 8601 format.
    pub time: String,
    /// A string that holds the level (INFO, WARN, ERROR, etc.).
    pub level: LogLevel,
    /// A string that holds the component name.
    pub component: String,
    /// A string that holds the description of the log message.
    pub description: String,
    /// A string that holds the log format.
    pub format: LogFormat,
}

impl Log {
    /// Logs a message to the console using a pre-allocated buffer to
    /// reduce memory allocation and flush the output buffer to ensure
    /// that the message is written immediately.
    ///
    /// # Errors
    ///
    /// This function will panic if an error occurs when writing to the
    /// pre-allocated buffer or flushing the output buffer.
    pub fn log(&self) -> io::Result<()> {
        // Open the file in append mode. If the file does not exist, create it.
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open("kyberlib.log")?;
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
                )
            }
            LogFormat::JSON => {
                writeln!(
                    file,
                    r#"{{"session_id": "{}", "timestamp": "{}", "description": "{}", "level": "{}", "component": "{}", "format": "{}"}}"#,
                    self.session_id,
                    self.time,
                    self.description,
                    self.level,
                    self.component,
                    self.format
                )
            }
            LogFormat::CEF => {
                writeln!(
                    file,
                    r#"[CEF]
                    <Event xmlns="http://www.w3.org/2003/05/events/Log">
                        <LogID>1</LogID>
                        <SourceName>kyberlib</SourceName>
                        <SourceType>Application</SourceType>
                        <EventReceivedTime>{}</EventReceivedTime>
                        <EventType>Log</EventType>
                        <Severity>{}</Severity>
                        <Message>{}</Message>
                        <SessionID>{}</SessionID>
                        <HostName>localhost</HostName>
                        <ComputerName>localhost</ComputerName>
                        <UserID>-</UserID>
                        <ThreadID>-</ThreadID>
                        <FileName>-</FileName>
                        <LineNumber>-</LineNumber>
                        <ProcessID>-</ProcessID>
                        <ModuleID>-</ModuleID>
                    </Event>
                    "#,
                    self.time,
                    self.level,
                    self.description,
                    self.session_id
                )
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported log format",
            )),
        }?;
        file.flush()?;
        Ok(())
    }

    /// Creates a new `Log` instance.
    ///
    /// Initializes a new `Log` struct with the provided details.
    ///
    /// # Returns
    ///
    /// Returns a new instance of the `Log` struct.
    pub fn new(
        session_id: &str,
        time: &str,
        level: LogLevel,
        component: &str,
        description: &str,
        format: LogFormat,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            time: time.to_string(),
            level,
            component: component.to_string(),
            description: description.to_string(),
            format,
        }
    }
}

/// Provides default values for `Log`.
///
/// This implementation provides a quick way to generate a `Log` instance with default values.
impl Default for Log {
    fn default() -> Self {
        Self {
            session_id: String::default(),
            time: String::default(),
            level: LogLevel::INFO, // Default log level
            component: String::default(),
            description: String::default(),
            format: LogFormat::CLF, // Default log format
        }
    }
}
#[cfg(test)]
/// Tests for the `log_info!` macro.
mod tests {
    use crate::kyberlib_log_info;

    #[test]
    fn test_log_info() {
        kyberlib_log_info!(
            LogLevel::INFO,
            "component",
            "description",
            LogFormat::CLF
        );
    }
}
