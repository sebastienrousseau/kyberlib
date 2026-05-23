#!/bin/bash
set -e

# This script runs a matrix of every valid feature combination, testing different security levels, nine-way optimization options, and AVX2 optimizations.

# Define variables
# KAT: Whether to run the known answer tests
# AVX2: Whether to run AVX2 code on x86 platforms with compiled GAS files
# NASM: Whether to run AVX2 code with both GAS and NASM files separately

# When setting AVX2 or NASM flags enable avx2 target features
# and LLVM address sanitser checks (requires nightly):
# export RUSTFLAGS="${RUSTFLAGS:-} -Z sanitizer=address -C target-cpu=native -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"

# Determine the host platform
TARGET=$(rustc -vV | sed -n 's|host: ||p') || true

# Set the RUSTFLAGS variable to the default value if it is not already set
RUSTFLAGS=${RUSTFLAGS:-""}

# Handle KAT flag
if [[ -z "${KAT}" ]]
  then
    echo Not running Known Answer Tests
  else
  echo Running Known Answer Tests
    RUSTFLAGS+=" --cfg KYBER_SECURITY_PARAMETERat"
fi

# Handle AVX2 flag
if [[ -z "${AVX2}" ]]
  then
    echo Not using AVX2 optimisations
    OPT=("")
  else
    echo Using AVX2 optimisations with GAS assembler
    OPT=("" "avx2")
fi

# Handle NASM flag
if [[ -n "${NASM}" ]]; then
    echo Using AVX2 optimisations with NASM assembler
    OPT+=("nasm")
fi

# Define a function to print headers
announce(){
  # Create a title bar with the specified text
  title="#    $1    #"
  edge=$(echo "${title}" | sed 's/./#/g')
  echo -e "\n\n${edge}"; echo "${title}"; echo -e "${edge}";
}

##############################################################

# Start time
start=$(date +%s)

# Announce the target platform
announce "${TARGET}"

# Define arrays for security levels and nine-way optimization options
LEVELS=("kyber512" "kyber768" "kyber1024")
NINES=("" "90s" "90s-fixslice")

# Iterate over security levels and nine-way optimization options, running the tests with different AVX2 optimization options
for level in "${LEVELS[@]}"; do
  for nine in "${NINES[@]}"; do
    for opt in "${OPT[@]}"; do
      # Construct the test name
      name="${level} ${nine} ${opt}"

      # Construct the feature string
      feat=${level:+"${level}"}${opt:+",${opt}"}${nine:+",${nine}"}

      # Announce the test
      announce "${name}"

      # Add the feature flags to RUSTFLAGS and run the tests
      RUSTFLAGS=${RUSTFLAGS} cargo test --features "${feat}"

      # Break out of the opt loop once one AVX2 optimization option has been tested
      break;
    done
  done
done

# End time
end=$(date +%s)

# Calculate the runtime
runtime=$((end-start))

# Announce the test runtime
announce "Test runtime: ${runtime} seconds"
