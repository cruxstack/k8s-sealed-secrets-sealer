#!/usr/bin/env bash
# End-to-end check of the local stack in a throwaway k3d cluster.
set -euo pipefail

export SEALER_CLUSTER="${SEALER_CLUSTER:-sealer-e2e}"
export SEALER_TILT_PORT="${SEALER_TILT_PORT:-10450}"
export SEALER_CONTROL_PLANE_PORT="${SEALER_CONTROL_PLANE_PORT:-4200}"
export SEALER_DYNAMODB_PORT="${SEALER_DYNAMODB_PORT:-4202}"
export SEALER_KMS_PORT="${SEALER_KMS_PORT:-4203}"
source .atmos/scripts/lib/dev.sh

port_forward_pid=""
cleanup() {
  local status=$?
  [[ -n "$port_forward_pid" ]] && kill "$port_forward_pid" 2>/dev/null
  [[ -n "${work:-}" ]] && rm -rf "$work"
  if [[ $status -ne 0 ]]; then
    echo "--- e2e failed; recent pod state ---" >&2
    kubectl --context "$KUBE_CONTEXT" get pods -A 2>&1 | grep -v kube-system >&2 || true
    echo "--- control plane log (last 40 lines) ---" >&2
    kubectl --context "$KUBE_CONTEXT" -n sealer-system logs deploy/sealer-control-plane --tail 40 >&2 || true
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
die() {
  echo "FAIL - $1" >&2
  exit 1
}

# can_proxy <agent cluster> <controller cluster>: whether that agent's service
# account may read that controller's certificate through the API proxy
can_proxy() {
  kubectl --context "$KUBE_CONTEXT" auth can-i get services/http:sealed-secrets-controller:http \
    --subresource=proxy \
    --as "system:serviceaccount:${1}-sealer:sealer-agent" \
    -n "${2}-sealed-secrets" >/dev/null 2>&1
}

# api <method> <path> [bearer] [json body]: calls the control plane and prints
# "<status> <body>"
api() {
  local method="$1" path="$2" auth="${3:-}" body="${4:-}" args=()
  args=(-sS -o "${work}/body" -w '%{http_code}' -X "$method" -H 'Content-Type: application/json')
  [[ -n "$auth" ]] && args+=(-H "Authorization: Bearer ${auth}")
  [[ -n "$body" ]] && args+=(--data "$body")
  printf '%s %s' "$(curl "${args[@]}" "${control_plane}${path}")" "$(/bin/cat "${work}/body")"
}

# login_status <token>: the HTTP status of logging in with a token
login_status() {
  api POST /agent/v1/session "" "$(jq -nc --arg t "$1" '{method: "k8s-oidc", token: $t}')" | cut -d' ' -f1
}

work="$(mktemp -d)"

ensure_cluster
pull_charts
build_binaries
echo "+ tilt ci --context ${KUBE_CONTEXT} --port ${SEALER_TILT_PORT}" >&2
tilt ci --context "$KUBE_CONTEXT" --port "$SEALER_TILT_PORT" --timeout "${E2E_TIMEOUT:-10m}"

# tilt ci closes its port forwards when it exits, so open one of our own
kubectl --context "$KUBE_CONTEXT" -n sealer-system port-forward svc/sealer-control-plane \
  "${SEALER_CONTROL_PLANE_PORT}:80" >/dev/null 2>&1 &
port_forward_pid=$!
control_plane="http://localhost:${SEALER_CONTROL_PLANE_PORT}"
for _ in $(seq 1 30); do
  curl -sf "${control_plane}/healthz" >/dev/null 2>&1 && break
  sleep 1
done

# --- control plane ---
[[ "$(curl -sf "${control_plane}/healthz" | jq -r .status)" == "ok" ]] || die "control plane is unhealthy"
check "control plane answers /healthz"

automount="$(kubectl --context "$KUBE_CONTEXT" -n sealer-system get deploy sealer-control-plane \
  -o jsonpath='{.spec.template.spec.automountServiceAccountToken}')"
[[ "$automount" == "false" ]] || die "control plane mounts a service account token"
check "control plane has no Kubernetes API token"

# --- agent login: only registered service accounts, only for this audience ---
audience="http://localhost:4100"
first="$(stack_clusters | head -n 1)"
kubectl --context "$KUBE_CONTEXT" -n "${first}-sealer" create serviceaccount e2e-rogue >/dev/null
rogue="$(kubectl --context "$KUBE_CONTEXT" -n "${first}-sealer" create token e2e-rogue --audience "$audience")"
[[ "$(login_status "$rogue")" == 401 ]] || die "an unregistered service account logged in"
check "login with an unregistered service account is refused"

wrong_aud="$(kubectl --context "$KUBE_CONTEXT" -n "${first}-sealer" create token sealer-agent --audience https://elsewhere.example.com)"
[[ "$(login_status "$wrong_aud")" == 401 ]] || die "a token for another audience logged in"
check "login with a token for another audience is refused"

registered="$(kubectl --context "$KUBE_CONTEXT" -n "${first}-sealer" create token sealer-agent --audience "$audience")"
[[ "$(login_status "$registered")" == 200 ]] || die "the registered service account could not log in"
check "login with the registered service account succeeds"

[[ "$(api POST /agent/v1/checkin "" '{}' | cut -d' ' -f1)" == 401 ]] || die "check-in without a session was accepted"
[[ "$(api POST /agent/v1/checkin "$registered" '{}' | cut -d' ' -f1)" == 401 ]] || die "a login token was accepted as a session"
check "check-in requires a session token"

[[ "$(api GET /api/v1/admin/fleet "" | cut -d' ' -f1)" == 401 ]] || die "admin API answered without a token"
check "admin API requires its token"

# --- fleet: every agent checks in with its controller's full key set ---
fleet=""
expected="$(stack_clusters | wc -l | tr -d ' ')"
for _ in $(seq 1 60); do
  fleet="$(api GET /api/v1/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
  healthy="$(jq '[.agents[] | select(.healthy)] | length' <<<"$fleet" 2>/dev/null || echo 0)"
  [[ "$healthy" == "$expected" ]] && break
  sleep 2
done
[[ "$healthy" == "$expected" ]] || die "only ${healthy}/${expected} agents are healthy: ${fleet}"
check "all ${expected} agents check in and are healthy"

while read -r name; do
  agent="$(jq --arg id "$name" '.agents[] | select(.id == $id)' <<<"$fleet")"
  [[ "$(jq -r .keys_complete <<<"$agent")" == true ]] || die "agent ${name} did not report its full key set"
  active="$(jq -r .controller.active_fingerprint <<<"$agent")"
  [[ "$active" == SHA256:* ]] || die "agent ${name} reported no active key"
  jq -e --arg fp "$active" '[.keys[].fingerprint] | index($fp) != null' <<<"$agent" >/dev/null \
    || die "agent ${name}'s key set lacks its active key"
  [[ "$(jq -r '.controller.key_renew_period + " " + .controller.key_order_priority' <<<"$agent")" == "720h0m0s CertNotBefore" ]] \
    || die "agent ${name} reported unexpected controller flags: $(jq -c .controller <<<"$agent")"
  check "agent ${name} reports its controller's keys and flags (${active})"

  # each agent may read only its own controller
  for other in $(stack_clusters); do
    allowed=no
    if can_proxy "$name" "$other"; then allowed=yes; fi
    [[ "$other" != "$name" || "$allowed" == yes ]] || die "agent ${name} cannot reach its own controller"
    [[ "$other" == "$name" || "$allowed" == no ]] || die "agent ${name} can reach the controller of ${other}"
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
  [[ "$got" == "$value" ]] || die "controller ${name} did not unseal into ${apps_ns}"
  check "controller ${name} unseals into ${apps_ns}"
done < <(stack_clusters)

# Until key sync exists, every simulated cluster generates its own key, so no
# key is held everywhere. A shared key would mean the clusters are not
# isolated from each other.
[[ "$(jq -r .keys_in_sync <<<"$fleet")" == false && "$(jq -r .env_key <<<"$fleet")" == null ]] \
  || die "the fleet reports an env key before key sync exists: $(jq -c .env_key <<<"$fleet")"
[[ "$(jq '[.agents[].keys[].fingerprint] | unique | length' <<<"$fleet")" == "$expected" ]] \
  || die "simulated clusters share keys"
jq -e --argjson n "$((expected - 1))" 'all(.agents[]; (.missing_keys | length) == $n)' <<<"$fleet" >/dev/null \
  || die "missing keys are not reported per cluster: $(jq -c '[.agents[] | {id, missing_keys}]' <<<"$fleet")"
check "keys are out of sync, and each cluster is missing the others' keys"

echo "e2e: ${passed} checks passed" >&2
