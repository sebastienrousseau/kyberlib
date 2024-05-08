// Copyright © 2024 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use kyberlib::{kyberlib_assert, kyberlib_max, kyberlib_min};
    use rlg::{log::Log, log_format::LogFormat, log_level::LogLevel};

    #[test]
    fn test_kyberlib_assert() {
        kyberlib_assert!(1 + 1 == 2);
    }

    #[test]
    fn test_kyberlib_min() {
        let min = kyberlib_min!(1, 2, 3);
        assert_eq!(min, 1);
    }

    #[test]
    fn test_kyberlib_max() {
        let max = kyberlib_max!(1, 2, 3);
        assert_eq!(max, 3);
    }

    #[test]
    fn test_kyberlib_info() {
        let log = Log::new(
            "12345",
            "2023-01-01T12:00:00Z",
            &LogLevel::INFO,
            "MyComponent",
            "This is a sample log message",
            &LogFormat::JSON,
        );

        assert_eq!(log.level, LogLevel::INFO);
    }

    #[test]
    fn test_kyberlib_error() {
        let log = Log::new(
            "12345",
            "2023-01-01T12:00:00Z",
            &LogLevel::ERROR,
            "MyComponent",
            "This is a sample log message",
            &LogFormat::JSON,
        );

        assert_eq!(log.level, LogLevel::ERROR);
    }

    #[test]
    fn test_kyberlib_debug() {
        let log = Log::new(
            "12345",
            "2023-01-01T12:00:00Z",
            &LogLevel::DEBUG,
            "MyComponent",
            "This is a sample log message",
            &LogFormat::JSON,
        );

        assert_eq!(log.level, LogLevel::DEBUG);
    }

    #[test]
    fn test_kyberlib_log() {
        let log = Log::new(
            "12345",
            "2023-02-28T12:34:56",
            &LogLevel::INFO,
            "MyComponent",
            "Hello world",
            &LogFormat::JSON,
        );

        assert_eq!(log.session_id, "12345");
        assert_eq!(log.time, "2023-02-28T12:34:56");
        assert_eq!(log.component, "MyComponent");
        assert_eq!(log.description, "Hello world");
        assert_eq!(log.format, LogFormat::JSON);
    }
}
