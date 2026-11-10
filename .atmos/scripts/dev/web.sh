#!/usr/bin/env bash
# Builds the web UI; Tilt runs this whenever the UI's source changes.
set -euo pipefail
source .atmos/scripts/lib/dev.sh
build_web
