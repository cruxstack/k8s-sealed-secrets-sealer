#!/usr/bin/env bash
# Shows the stack's pods, each agent's active controller key, and endpoints.
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
echo "Active controller keys (from agent logs):" >&2
kubectl --context "$KUBE_CONTEXT" get deploy -A -l app.kubernetes.io/name=k8s-sealed-secrets-sealer-agent \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' \
  | while read -r namespace deployment; do
      fingerprint="$(log_events "$namespace" "$deployment" controller.key_active | tail -n 1 | jq -r '.fingerprint // empty')"
      printf '  %-28s %s\n' "$namespace" "${fingerprint:-(none yet)}" >&2
    done

cat >&2 <<EOF

  Cluster:        ${SEALER_CLUSTER} (context ${KUBE_CONTEXT})
  Tilt:           http://localhost:${SEALER_TILT_PORT}
  Control plane:  http://localhost:${SEALER_CONTROL_PLANE_PORT}
  DynamoDB Local: http://localhost:${SEALER_DYNAMODB_PORT}
  KMS (local):    http://localhost:${SEALER_KMS_PORT}
EOF
