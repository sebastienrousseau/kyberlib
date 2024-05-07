// Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use core::fmt;
    use core::result::Result as CoreResult;
    use kyberlib::loggers::*;

    // Assuming a maximum log message size, adjust as needed
    const MAX_LOG_SIZE: usize = 1024;

    struct CustomFile {
        data: [u8; MAX_LOG_SIZE],
        len: usize,
    }

    impl fmt::Write for CustomFile {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            let bytes_len = bytes.len();
            if self.len + bytes_len > MAX_LOG_SIZE {
                return Err(fmt::Error); // Buffer overflow
            }

            self.data[self.len..self.len + bytes_len].copy_from_slice(bytes);
            self.len += bytes_len;

            Ok(())
        }
    }

    impl CustomWrite for CustomFile {
        fn custom_flush(&mut self) -> CoreResult<(), CustomError> {
            Ok(())
        }
    }

    #[test]
    fn test_log_info() {
        let mut custom_file = CustomFile {
            data: [0; MAX_LOG_SIZE],
            len: 0,
        };
        let log_entry = Log::new(
            "session123",
            "2023-11-20T12:34:56",
            LogLevel::INFO,
            "component_name",
            "This is a log message",
            LogFormat::CLF,
        );

        assert!(log_entry.log(&mut custom_file).is_ok());

        // Convert the written bytes to a string slice for checking
        let logged_data = core::str::from_utf8(&custom_file.data[..custom_file.len])
            .expect("Failed to convert to string");

        // Here you can assert the contents of `logged_data`
        // For example, checking if it contains certain substrings
        assert!(logged_data.contains("This is a log message"));
    }
}
