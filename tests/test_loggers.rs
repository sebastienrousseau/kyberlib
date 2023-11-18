// Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    fn kyberlib_log_info(
        level: LogLevel,
        component: &str,
        description: &str,
        format: LogFormat,
    ) {
        let log =
        kyberlib_log_info!(level, component, description, format);
        assert_eq!(log.level, level);
        assert_eq!(log.component, component);
        assert_eq!(log.description, description);
        assert_eq!(log.format, format);
        }

    #[test]
    fn test_macros() {
        kyberlib_log_info(
            LogLevel::ALL,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::DEBUG,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::DISABLED,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::ERROR,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::FATAL,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::INFO,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::NONE,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::TRACE,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::VERBOSE,
            "component",
            "description",
            LogFormat::CLF,
        );
        kyberlib_log_info(
            LogLevel::WARNING,
            "component",
            "description",
            LogFormat::CLF,
        );
    }

    use kyberlib::{
        loggers::{Log, LogFormat, LogLevel},
        kyberlib_log_info,
    };

    #[test]
    fn test_log_level_display() {
        let level = LogLevel::INFO;
        assert_eq!(format!("{level}"), "INFO");
    }

    #[test]
    fn test_log_format_display() {
        let format = LogFormat::JSON;
        assert_eq!(format!("{format}"), "JSON\n");
    }

    #[test]
    fn test_log_new() {
        let log = Log::new(
            "session123",
            "2023-02-28T12:34:56Z",
            LogLevel::WARNING,
            "auth",
            "Invalid credentials",
            LogFormat::CLF,
        );

        assert_eq!(log.session_id, "session123");
        assert_eq!(log.time, "2023-02-28T12:34:56Z");
        assert_eq!(log.level, LogLevel::WARNING);
        assert_eq!(log.component, "auth");
        assert_eq!(log.description, "Invalid credentials");
        assert_eq!(log.format, LogFormat::CLF);
    }

    #[test]
    fn test_log_default() {
        let log = Log::default();

        assert!(log.session_id.is_empty());
        assert!(log.time.is_empty());
        assert_eq!(log.level, LogLevel::INFO);
        assert!(log.component.is_empty());
        assert!(log.description.is_empty());
        assert_eq!(log.format, LogFormat::CLF);
    }
}
