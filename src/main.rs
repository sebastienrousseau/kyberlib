// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The main function of the program.
//!
//! Calls the `run()` function from the `ssg` module to run the static site generator.
//!
//! If an error occurs while running the `run()` function, the function prints an error message
//! to standard error and exits the program with a non-zero status code.
fn main() {
    // Call the `run()` function from the `kyberlib` module.
    if let Err(err) = kyberlib::run() {
        eprintln!("Error running kyberlib: {}", err);
        std::process::exit(1);
    }
}
