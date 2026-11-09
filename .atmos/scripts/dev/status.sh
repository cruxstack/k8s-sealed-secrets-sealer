#!/usr/bin/env bash
# Shows the stack's pods, the fleet as the control plane sees it, and the
# local endpoints.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

if ! cluster_exists; then
  echo "The local cluster ${SEALER_CLUSTER} does not exist. Start it with 'atmos dev up'." >&2
  exit 0
fi

kubectl --context "$KUBE_CONTEXT" get pods -A \
  -l 'app.kubernetes.io/name in (k8s-sealed-secrets-sealer-agent,k8s-sealed-secrets-sealer-control-plane,sealed-secrets,sealer-emulator)' \
  -o custom-columns='NAMESPACE:.metadata.namespace,POD:.metadata.name,READY:.status.containerStatuses[*].ready,STATUS:.status.phase'

echo >&2
# the fleet comes from the control plane's admin API, through Tilt's port forward
if fleet="$(curl -sf -H "Authorization: Bearer ${LOCAL_ADMIN_TOKEN}" \
  "http://localhost:${SEALER_CONTROL_PLANE_PORT}/api/v1/admin/fleet" 2>/dev/null)"; then
  jq -r '
    "Fleet (env " + .env + "): env key " + (if .env_key then .env_key.fingerprint else "none, keys out of sync" end),
    "",
    (["AGENT", "REGION", "HEALTHY", "KEYS", "MISSING", "ACTIVE KEY"] | @tsv),
    (.agents[] | [.id, .region, (.healthy | tostring), (.keys // [] | length | tostring),
      (.missing_keys // [] | length | tostring), (.controller.active_fingerprint // "-")] | @tsv)
  ' <<<"$fleet" | column -t -s $'\t' >&2
else
  echo "Fleet: the control plane is not reachable on localhost:${SEALER_CONTROL_PLANE_PORT} (is Tilt running?)" >&2
fi

/bin/cat >&2 <<EOF

  Cluster:        ${SEALER_CLUSTER} (context ${KUBE_CONTEXT})
  Tilt:           http://localhost:${SEALER_TILT_PORT}
  Control plane:  http://localhost:${SEALER_CONTROL_PLANE_PORT}
  DynamoDB Local: http://localhost:${SEALER_DYNAMODB_PORT}
  KMS (local):    http://localhost:${SEALER_KMS_PORT}
EOF
