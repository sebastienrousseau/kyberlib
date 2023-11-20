// Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use kyberlib::loggers::Log;
    use kyberlib::{
        kyberlib_assert, kyberlib_debug, kyberlib_error, kyberlib_info, kyberlib_max, kyberlib_min,kyberlib_log,
        loggers::{LogFormat, LogLevel},
    };

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
        let log = kyberlib_info!(
            "session123",
            "2023-11-20T12:34:56",
            "component",
            "description",
            LogFormat::CLF
        );

        assert_eq!(log.level, LogLevel::INFO);
    }

    #[test]
    fn test_kyberlib_error() {
        let log = kyberlib_error!(
            "session456",
            "2023-11-20T13:45:23",
            "component",
            "description",
            LogFormat::CLF
        );

        assert_eq!(log.level, LogLevel::ERROR);
    }

    #[test]
    fn test_kyberlib_debug() {
        let log = kyberlib_debug!(
            "session789",
            "2023-11-20T14:56:34",
            "component",
            "description",
            LogFormat::CLF
        );

        assert_eq!(log.level, LogLevel::DEBUG);
    }

    #[test]
    fn test_kyberlib_log() {
        let log = kyberlib_log!(
            "session123",
            "2023-02-28T12:34:56",
            "mycomponent",
            "Hello world",
            LogFormat::CLF
        );

        assert_eq!(log.session_id, "session123");
        assert_eq!(log.time, "2023-02-28T12:34:56");
        assert_eq!(log.component, "mycomponent");
        assert_eq!(log.description, "Hello world");
        assert_eq!(log.format, LogFormat::CLF);
    }
}
