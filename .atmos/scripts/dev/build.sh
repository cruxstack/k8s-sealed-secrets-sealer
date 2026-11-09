#!/usr/bin/env bash
# Builds the stack's Linux binaries; Tilt runs this whenever Go code changes.
set -euo pipefail
source .atmos/scripts/lib/dev.sh
build_binaries
