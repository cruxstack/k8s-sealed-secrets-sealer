#!/usr/bin/env bash
# End-to-end check of the local stack in a throwaway k3d cluster.
set -euo pipefail

export SEALER_CLUSTER="${SEALER_CLUSTER:-sealer-e2e}"
export SEALER_TILT_PORT="${SEALER_TILT_PORT:-10450}"
export SEALER_CONTROL_PLANE_PORT="${SEALER_CONTROL_PLANE_PORT:-4200}"
export SEALER_DYNAMODB_PORT="${SEALER_DYNAMODB_PORT:-4202}"
export SEALER_KMS_PORT="${SEALER_KMS_PORT:-4203}"
export SEALER_GITHUB_PORT="${SEALER_GITHUB_PORT:-4204}"
source .atmos/scripts/lib/dev.sh

port_forward_pids=()
cleanup() {
  local status=$?
  for pid in "${port_forward_pids[@]}"; do kill "$pid" 2>/dev/null; done
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
build_web
build_binaries
echo "+ tilt ci --context ${KUBE_CONTEXT} --port ${SEALER_TILT_PORT}" >&2
tilt ci --context "$KUBE_CONTEXT" --port "$SEALER_TILT_PORT" --timeout "${E2E_TIMEOUT:-10m}"

# tilt ci closes its port forwards when it exits, so open our own, on the
# same ports the stack's URLs (OAuth redirects, token audience) point at
kubectl --context "$KUBE_CONTEXT" -n sealer-system port-forward svc/sealer-control-plane \
  "${SEALER_CONTROL_PLANE_PORT}:80" >/dev/null 2>&1 &
port_forward_pids+=($!)
kubectl --context "$KUBE_CONTEXT" -n sealer-system port-forward svc/mock-github \
  "${SEALER_GITHUB_PORT}:8080" >/dev/null 2>&1 &
port_forward_pids+=($!)
control_plane="http://localhost:${SEALER_CONTROL_PLANE_PORT}"
for _ in $(seq 1 30); do
  curl -sf "${control_plane}/healthz" >/dev/null 2>&1 \
    && curl -sf "http://localhost:${SEALER_GITHUB_PORT}/healthz" >/dev/null 2>&1 && break
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
audience="$control_plane"
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

# --- web UI and sign-in ---
headers="$(curl -sS -D - -o "${work}/index.html" "${control_plane}/fleet")"
grep -qi "^content-security-policy:.*script-src 'self'" <<<"$headers" || die "the UI has no strict content security policy"
grep -qi "^x-frame-options: DENY" <<<"$headers" || die "the UI can be framed"
grep -q 'type="module"' "${work}/index.html" || die "the UI is not served"
check "web UI is served, with a strict content security policy"

[[ "$(api GET /api/v1/fleet "" | cut -d' ' -f1)" == 401 ]] || die "the fleet API answered without sign-in"
check "the fleet API requires sign-in"

# sign_in <login>: runs the browser's side of GitHub sign-in against the
# mock and prints where the control plane finally sent the browser
sign_in() {
  local jar="${work}/cookies-$1" next
  next="$(curl -sS -o /dev/null -w '%{redirect_url}' -c "$jar" -b "$jar" "${control_plane}/api/v1/auth/login?return_to=/fleet")"
  next="$(curl -sS -o /dev/null -w '%{redirect_url}' "${next}&login=$1")"
  curl -sS -o /dev/null -w '%{redirect_url}' -c "$jar" -b "$jar" "$next"
}

[[ "$(sign_in alice)" == "${control_plane}/fleet" ]] || die "alice could not sign in"
me="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/auth/me")"
[[ "$(jq -r .user.login <<<"$me")" == alice ]] || die "/me after sign-in: ${me}"
csrf="$(jq -r .csrf_token <<<"$me")"
agents="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/fleet" | jq '.agents | length')"
[[ "$agents" == "$(stack_clusters | wc -l | tr -d ' ')" ]] || die "the signed-in fleet has ${agents} agents"
check "alice (org member, allowed team) signs in and sees the fleet"

# --- repositories, through the GitHub App, limited to alice's own access ---
repos="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/repos")"
[[ "$(jq -c '[.repositories[] | .full_name + ":" + .access]' <<<"$repos")" == '["example-org/apps:write","example-org/platform:read"]' ]] \
  || die "alice's repositories: ${repos}"
check "alice sees only the repositories she can read, with her access"

files="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/repos/example-org/apps/files")"
jq -e '
  (.files | map(.path)) == ["deploy/billing/sealed-secret.yaml", "deploy/legacy/sealed-secret.yaml", "deploy/search/sealed-secret.yaml"]
  and (.files[0].documents | map(.namespace)) == ["dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"]
  and (.files[1].documents[0].problem | test("cluster-wide"))
' <<<"$files" >/dev/null || die "SealedSecret discovery in example-org/apps: ${files}"
check "discovery finds the dev SealedSecrets in example-org/apps, and flags cluster-wide scope"

restricted="$(curl -sS -o /dev/null -w '%{http_code}' -b "${work}/cookies-alice" "${control_plane}/api/v1/repos/example-org/restricted/files")"
[[ "$restricted" == 404 ]] || die "alice read a repository she has no access to: ${restricted}"
check "a repository alice cannot read is not found"

[[ "$(sign_in bob)" == "${control_plane}/login?error=not_in_team" ]] || die "bob was not refused as outside the allowed team"
[[ "$(sign_in carol)" == "${control_plane}/login?error=not_member" ]] || die "carol was not refused as outside the org"
check "sign-in refuses users outside the allowed team or the org"

logout() { curl -sS -o /dev/null -w '%{http_code}' -X POST -b "${work}/cookies-alice" -c "${work}/cookies-alice" "$@" "${control_plane}/api/v1/auth/logout"; }
[[ "$(logout)" == 403 ]] || die "sign-out without the csrf token was accepted"
[[ "$(logout -H "X-CSRF-Token: ${csrf}")" == 204 ]] || die "sign-out with the csrf token failed"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -b "${work}/cookies-alice" "${control_plane}/api/v1/auth/me")" == 401 ]] \
  || die "still signed in after sign-out"
check "sign-out requires the csrf token and ends the session"

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

[[ "$(api GET "/agent/v1/escrow/SHA256:x" "" | cut -d' ' -f1)" == 401 ]] || die "escrow answered without a session"
[[ "$(api GET "/agent/v1/commands" "" | cut -d' ' -f1)" == 401 ]] || die "commands answered without a session"
check "escrow and commands require a session token"

# --- key sync: every simulated cluster starts with its own key. Agents
# escrow them, each cluster restores the others' keys from escrow, and the
# control plane turns key renewal on in exactly one cluster. ---
synced() {
  jq -e --argjson n "$expected" '
    .keys_in_sync
    and ([.agents[] | select(.healthy and (.keys | length) == $n and (.missing_keys | length) == 0)] | length) == $n
    and ([.agents[] | select(.controller.key_renew_period != "0s")] | length) == 1
  ' <<<"$1" >/dev/null 2>&1
}
for _ in $(seq 1 120); do
  fleet="$(api GET /api/v1/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
  synced "$fleet" && break
  sleep 2
done
synced "$fleet" || die "keys did not converge: $(jq -c '{keys_in_sync, env_key: .env_key.fingerprint, agents: [.agents[] | {id, healthy, keys: [.keys[].fingerprint], missing_keys, active: .controller.active_fingerprint, renew: .controller.key_renew_period}]}' <<<"$fleet")"
env_key="$(jq -r .env_key.fingerprint <<<"$fleet")"
check "keys converge: every cluster holds all ${expected} keys (env key ${env_key})"

restored=0
for name in $(stack_clusters); do
  n="$(kubectl --context "$KUBE_CONTEXT" -n "${name}-sealed-secrets" get secrets \
    -l sealedsecrets.bitnami.com/sealed-secrets-key=active -o json \
    | jq '[.items[] | select(.metadata.annotations["sealer.cruxstack.io/restored-from"] == "escrow")] | length')"
  [[ "$n" == "$((expected - 1))" ]] || die "cluster ${name} restored ${n} keys from escrow, want $((expected - 1))"
  restored=$((restored + n))
done
check "each cluster restored the other clusters' keys from escrow (${restored} restores)"

escrowed="$(log_events sealer-system sealer-control-plane key.escrowed | wc -l | tr -d ' ')"
[[ "$escrowed" == "$expected" ]] || die "the control plane logged ${escrowed} key.escrowed events, want ${expected}"
check "the control plane logged key.escrowed once per key"

renewing="$(jq -r '[.agents[] | select(.controller.key_renew_period != "0s") | .id] | join(",")' <<<"$fleet")"
[[ "$renewing" == "$(stack_clusters | sort | head -n 1)" ]] || die "renewal was turned on in ${renewing}, want the lowest agent ID"
args="$(kubectl --context "$KUBE_CONTEXT" -n "${renewing}-sealed-secrets" get deploy sealed-secrets-controller \
  -o jsonpath='{.spec.template.spec.containers[0].args}')"
grep -Eq -- '--key-renew-period(=|",")720h0m0s"' <<<"$args" || die "controller ${renewing} args do not renew: ${args}"
check "key renewal is on in exactly one cluster (${renewing})"

# The env key's certificate, from a cluster that restored it from escrow.
# The simulated controllers generate their keys in the same second, so each
# may prefer its own key as active; the env key is the control plane's
# deterministic choice among them, and sealing uses it.
for name in $(stack_clusters); do
  kubectl --context "$KUBE_CONTEXT" -n "${name}-sealed-secrets" get secrets \
    -l sealedsecrets.bitnami.com/sealed-secrets-key=active -o json \
    | jq -r --arg fp "$env_key" '.items[] | select(.metadata.annotations["sealer.cruxstack.io/fingerprint"] == $fp)
        | .data["tls.crt"]' | head -n 1 | base64 -d >"${work}/env-key.pem" 2>/dev/null || true
  [[ -s "${work}/env-key.pem" ]] && break
done
[[ -s "${work}/env-key.pem" ]] || die "no cluster restored the env key ${env_key}"

while read -r name; do
  agent="$(jq --arg id "$name" '.agents[] | select(.id == $id)' <<<"$fleet")"
  [[ "$(jq -r .keys_complete <<<"$agent")" == true ]] || die "agent ${name} did not report its full key set"
  active="$(jq -r .controller.active_fingerprint <<<"$agent")"
  [[ "$active" == SHA256:* ]] || die "agent ${name} reported no active key"
  jq -e --arg fp "$active" '[.keys[].fingerprint] | index($fp) != null' <<<"$agent" >/dev/null \
    || die "agent ${name}'s key set lacks its active key"
  [[ "$(jq -r .controller.key_order_priority <<<"$agent")" == CertNotBefore ]] \
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

  # A value sealed with the env key's certificate unseals in every cluster:
  # in all but the one that generated it, the key arrived through escrow.
  apps_ns="${name}-apps"
  value="e2e-$(openssl rand -hex 12)"
  kubectl --context "$KUBE_CONTEXT" create secret generic e2e-roundtrip -n "$apps_ns" \
    --from-literal=value="$value" --dry-run=client -o json \
    | kubeseal --cert "${work}/env-key.pem" --scope strict --format yaml \
    | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
  got=""
  for _ in $(seq 1 30); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "$apps_ns" get secret e2e-roundtrip \
      -o jsonpath='{.data.value}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 2
  done
  [[ "$got" == "$value" ]] || die "controller ${name} did not unseal into ${apps_ns}"
  check "controller ${name} unseals a value sealed with the env key into ${apps_ns}"
done < <(stack_clusters)

echo "e2e: ${passed} checks passed" >&2
