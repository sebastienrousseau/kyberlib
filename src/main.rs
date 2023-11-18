// SPDX-FileCopyrightText: Copyright © 2023 kyberlib. All rights reserved.
// SPDX-License-Identifier: MIT

/// This is the main entry point for the kyberlib application.
fn main() {
    // Call the `run()` function from the `kyberlib` module.
    if let Err(err) = kyberlib::run() {
        eprintln!("Error running kyberlib: {}", err);
        std::process::exit(1);
    }
}
