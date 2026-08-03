//! Sound compatibility implementation of the small `atty` 0.2 API.
//!
//! This crate exists only for the legacy Clap 2 dependency used by the
//! dudect benchmark harness. Rust's standard library has provided the
//! required terminal detection since Rust 1.70.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal};

/// Standard stream whose terminal state should be queried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stream {
    /// Standard input.
    Stdin,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Returns whether the selected standard stream is connected to a terminal.
#[must_use]
pub fn is(stream: Stream) -> bool {
    match stream {
        Stream::Stdin => io::stdin().is_terminal(),
        Stream::Stdout => io::stdout().is_terminal(),
        Stream::Stderr => io::stderr().is_terminal(),
    }
}

/// Returns whether the selected standard stream is not a terminal.
#[must_use]
pub fn isnt(stream: Stream) -> bool {
    !is(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_and_isnt_are_complements_for_every_stream() {
        for stream in [Stream::Stdin, Stream::Stdout, Stream::Stderr] {
            assert_ne!(is(stream), isnt(stream));
        }
    }
}
