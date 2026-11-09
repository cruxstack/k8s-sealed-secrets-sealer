#!/usr/bin/env bash
# Deletes the local cluster and its registry. Sealing keys and all other data
# in the cluster are lost.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

if [[ "${DEV_YES:-}" != "true" ]]; then
  printf 'This deletes the k3d cluster %s and everything in it. Continue? [y/N] ' "$SEALER_CLUSTER" >&2
  read -r answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 0
fi
delete_cluster
echo "Deleted ${SEALER_CLUSTER}." >&2
