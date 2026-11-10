#!/usr/bin/env bash
# Prepares the cluster, chart and binaries, then runs Tilt.
#   tilt.sh up [tilt args]   interactive development
#   tilt.sh ci [tilt args]   bring the stack up once, wait until ready, exit
set -euo pipefail
source .atmos/scripts/lib/dev.sh

action="${1:?Usage: tilt.sh <up|ci> [tilt args]}"
shift

ensure_cluster
pull_charts
build_web
build_binaries

echo "+ tilt ${action} --context ${KUBE_CONTEXT} --port ${SEALER_TILT_PORT} $*" >&2
exec tilt "$action" --context "$KUBE_CONTEXT" --port "$SEALER_TILT_PORT" "$@"
