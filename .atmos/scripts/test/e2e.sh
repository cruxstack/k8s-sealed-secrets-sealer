#!/usr/bin/env bash
# End-to-end check of the local stack in a throwaway k3d cluster.
set -euo pipefail

export SEALER_CLUSTER="${SEALER_CLUSTER:-sealer-e2e}"
export SEALER_TILT_PORT="${SEALER_TILT_PORT:-10450}"
export SEALER_CONTROL_PLANE_PORT="${SEALER_CONTROL_PLANE_PORT:-4200}"
export SEALER_DYNAMODB_PORT="${SEALER_DYNAMODB_PORT:-4202}"
export SEALER_KMS_PORT="${SEALER_KMS_PORT:-4203}"
source .atmos/scripts/lib/dev.sh

cleanup() {
  local status=$?
  [[ -n "${work:-}" ]] && rm -rf "$work"
  if [[ $status -ne 0 ]]; then
    echo "--- e2e failed; recent pod state ---" >&2
    kubectl --context "$KUBE_CONTEXT" get pods -A 2>&1 | grep -v kube-system >&2 || true
  fi
  if [[ "${E2E_KEEP:-}" == "true" ]]; then
    echo "Keeping ${SEALER_CLUSTER} (context ${KUBE_CONTEXT}). Remove it with: SEALER_CLUSTER=${SEALER_CLUSTER} atmos dev destroy --yes" >&2
  else
    delete_cluster || true
  fi
  exit "$status"
}
trap cleanup EXIT

passed=0
check() {
  echo "ok - $1" >&2
  passed=$((passed + 1))
}

# can_proxy <agent cluster> <controller cluster>: whether that agent's service
# account may read that controller's certificate through the API proxy
can_proxy() {
  kubectl --context "$KUBE_CONTEXT" auth can-i get services/http:sealed-secrets-controller:http \
    --subresource=proxy \
    --as "system:serviceaccount:${1}-sealer:sealer-agent" \
    -n "${2}-sealed-secrets" >/dev/null 2>&1
}

work="$(mktemp -d)"

ensure_cluster
pull_charts
build_binaries
echo "+ tilt ci --context ${KUBE_CONTEXT} --port ${SEALER_TILT_PORT}" >&2
tilt ci --context "$KUBE_CONTEXT" --port "$SEALER_TILT_PORT" --timeout "${E2E_TIMEOUT:-10m}"

# --- control plane ---
health="$(kubectl --context "$KUBE_CONTEXT" get --raw \
  "/api/v1/namespaces/sealer-system/services/sealer-control-plane:http/proxy/healthz")"
[[ "$(jq -r .status <<<"$health")" == "ok" ]] || { echo "control plane is unhealthy: ${health}" >&2; exit 1; }
check "control plane answers /healthz"

# The control plane must not be able to reach the Kubernetes API.
automount="$(kubectl --context "$KUBE_CONTEXT" -n sealer-system get deploy sealer-control-plane \
  -o jsonpath='{.spec.template.spec.automountServiceAccountToken}')"
[[ "$automount" == "false" ]] || { echo "control plane mounts a service account token" >&2; exit 1; }
check "control plane has no Kubernetes API token"

# --- simulated clusters ---
fingerprints=()
while read -r name; do
  fingerprint="$(log_events "${name}-sealer" sealer-agent controller.key_active | tail -n 1 | jq -r '.fingerprint // empty')"
  [[ "$fingerprint" == SHA256:* ]] || { echo "agent ${name} reported no controller key" >&2; exit 1; }
  fingerprints+=("$fingerprint")
  check "agent ${name} reads its controller's key (${fingerprint})"

  # each agent may read only its own controller
  for other in $(stack_clusters); do
    allowed=no
    if can_proxy "$name" "$other"; then allowed=yes; fi
    if [[ "$other" == "$name" && "$allowed" != yes ]]; then
      echo "agent ${name} cannot reach its own controller through the API proxy" >&2
      exit 1
    fi
    if [[ "$other" != "$name" && "$allowed" == yes ]]; then
      echo "agent ${name} can reach the controller of ${other}" >&2
      exit 1
    fi
  done
  check "agent ${name} can reach only its own controller"

  # The controller really serves its apps namespace: a value sealed with its
  # certificate comes back as the same plaintext Secret.
  apps_ns="${name}-apps"
  value="e2e-$(openssl rand -hex 12)"
  kubectl --context "$KUBE_CONTEXT" get --raw \
    "/api/v1/namespaces/${name}-sealed-secrets/services/http:sealed-secrets-controller:http/proxy/v1/cert.pem" >"${work}/${name}.pem"
  kubectl --context "$KUBE_CONTEXT" create secret generic e2e-roundtrip -n "$apps_ns" \
    --from-literal=value="$value" --dry-run=client -o json \
    | kubeseal --cert "${work}/${name}.pem" --scope strict --format yaml \
    | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
  got=""
  for _ in $(seq 1 30); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "$apps_ns" get secret e2e-roundtrip \
      -o jsonpath='{.data.value}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 2
  done
  [[ "$got" == "$value" ]] || { echo "controller ${name} did not unseal into ${apps_ns}" >&2; exit 1; }
  check "controller ${name} unseals into ${apps_ns}"
done < <(stack_clusters)

# Until key sync exists, every simulated cluster generates its own key. Equal
# fingerprints would mean the clusters are not isolated from each other.
unique="$(printf '%s\n' "${fingerprints[@]}" | sort -u | wc -l | tr -d ' ')"
[[ "$unique" == "${#fingerprints[@]}" ]] || { echo "simulated clusters share keys: ${fingerprints[*]}" >&2; exit 1; }
check "simulated clusters hold separate keys"

echo "e2e: ${passed} checks passed" >&2
