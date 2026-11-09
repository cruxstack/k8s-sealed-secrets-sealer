#!/usr/bin/env bash
# Removes the stack's workloads (tilt down) and keeps the cluster for reuse.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

if ! cluster_exists; then
  echo "The local cluster ${SEALER_CLUSTER} does not exist; nothing to take down." >&2
  exit 0
fi
k3d cluster start "$SEALER_CLUSTER" >/dev/null
pull_charts
exec tilt down --context "$KUBE_CONTEXT" "$@"
