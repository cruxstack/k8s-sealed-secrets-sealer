#!/usr/bin/env bash
# Shows the stack's pods, each env's fleet as the control plane sees it, and
# the local endpoints.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

if ! cluster_exists; then
  echo "The local cluster ${SEALER_CLUSTER} does not exist. Start it with 'atmos dev up'." >&2
  exit 0
fi

kubectl --context "$KUBE_CONTEXT" get pods -A \
  -l 'app.kubernetes.io/name in (k8s-sealed-secrets-sealer-agent,k8s-sealed-secrets-sealer-control-plane,sealed-secrets,sealer-emulator)' \
  -o custom-columns='NAMESPACE:.metadata.namespace,POD:.metadata.name,READY:.status.containerStatuses[*].ready,STATUS:.status.phase'

# Each env's fleet comes from the control plane's admin API, through Tilt's
# port forward. The stack serves several envs on one URL, so each is asked
# for under its own path: /api/v1/admin/fleet answers only with one env.
control_plane="http://localhost:${SEALER_CONTROL_PLANE_PORT}"
if ! curl -sf -o /dev/null "${control_plane}/healthz" 2>/dev/null; then
  echo >&2
  echo "Fleet: the control plane is not reachable on localhost:${SEALER_CONTROL_PLANE_PORT} (is Tilt running?)" >&2
else
  for env in $(stack_envs); do
    echo >&2
    if ! fleet="$(curl -sf -H "Authorization: Bearer ${LOCAL_ADMIN_TOKEN}" \
      "${control_plane}/api/v1/envs/${env}/admin/fleet" 2>/dev/null)"; then
      echo "Fleet (env ${env}): the control plane did not return it" >&2
      continue
    fi
    jq -r '
      "Fleet (env " + .env + "): env key " + (
        if .env_key then .env_key.fingerprint
        elif ([.agents[] | select(.checked_in)] | length) == 0 then "none, no cluster has checked in"
        else "none, keys out of sync" end) + "\n"
    ' <<<"$fleet" >&2
    jq -r '
      (["AGENT", "REGION", "HEALTHY", "KEYS", "MISSING", "ACTIVE KEY"] | @tsv),
      (.agents[] | [.id, .region, (.healthy | tostring), (.keys // [] | length | tostring),
        (.missing_keys // [] | length | tostring), (.controller.active_fingerprint // "-")] | @tsv)
    ' <<<"$fleet" | column -t -s $'\t' >&2
  done
fi

/bin/cat >&2 <<EOF

  Cluster:        ${SEALER_CLUSTER} (context ${KUBE_CONTEXT})
  Tilt:           http://localhost:${SEALER_TILT_PORT}
  Web UI:         http://localhost:${SEALER_CONTROL_PLANE_PORT}  (sign in as alice)
  DynamoDB Local: http://localhost:${SEALER_DYNAMODB_PORT}
  KMS (local):    http://localhost:${SEALER_KMS_PORT}
  GitHub (mock):  http://localhost:${SEALER_GITHUB_PORT}
EOF
