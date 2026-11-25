#!/bin/bash
set -e

# This script runs a matrix of every valid feature combination, testing each security level with and without the 90s variants.

# Define variables
# KAT: Whether to run the known answer tests

# Optional LLVM address sanitizer checks (requires nightly):
# export RUSTFLAGS="${RUSTFLAGS:-} -Z sanitizer=address"

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

OPT=("")

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

# Iterate over security levels and nine-way optimization options, running the tests
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

    done
  done
done

# End time
end=$(date +%s)

# Calculate the runtime
runtime=$((end-start))

# Announce the test runtime
announce "Test runtime: ${runtime} seconds"
