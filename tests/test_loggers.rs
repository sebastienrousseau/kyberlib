// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    use rlg::{log::Log, log_format::LogFormat, log_level::LogLevel};

    #[test]
    fn test_log_info() {
        let log_entry = Log::new(
            "session123",
            "2023-11-20T12:34:56",
            &LogLevel::INFO,
            "component_name",
            "This is a log message",
            &LogFormat::CLF,
        );
        assert_eq!(log_entry.level, LogLevel::INFO);
        assert_eq!(log_entry.session_id, "session123");
        assert_eq!(log_entry.time, "2023-11-20T12:34:56");
        assert_eq!(log_entry.component, "component_name");
        assert_eq!(log_entry.description, "This is a log message");
        assert_eq!(log_entry.format, LogFormat::CLF);
    }
}
