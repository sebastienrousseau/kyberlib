# Renders .github/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Run `make demo` from the repository root. Everything shown is real output
# from this repository: a typed ML-KEM-768 round trip, then the NIST ACVP
# vectors for all three parameter sets.

Output .github/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 640
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Build first so the recording shows results, not compilation.
Hide
Type "cargo build -q -p kyberlib --example typed_kem && RUSTFLAGS='--cfg KYBER_SECURITY_PARAMETERat' cargo test -q -p kyberlib --test test_acvp --no-run 2>/dev/null; clear"
Enter
Sleep 120s
Show

Type "cargo run -q -p kyberlib --example typed_kem"
Enter
Sleep 3s

Type "make acvp 2>/dev/null | grep -E 'ACVP|ML-KEM|test result'"
Enter
Sleep 12s
