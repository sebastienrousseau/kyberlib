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

# The parameter set is a type, not a feature (#158): every build tests
# all three. Iterate over the symmetric-primitive and optimisation options.
NINES=("" "90s" "90s-fixslice")

for nine in "${NINES[@]}"; do
  for opt in "${OPT[@]}"; do
    name="${nine:-default} ${opt}"
    feat=${opt}${nine:+",${nine}"}
    feat=${feat#,}

    announce "${name}"
    RUSTFLAGS=${RUSTFLAGS} cargo test ${feat:+--features "${feat}"}
  done
done

# End time
end=$(date +%s)

# Calculate the runtime
runtime=$((end-start))

# Announce the test runtime
announce "Test runtime: ${runtime} seconds"
