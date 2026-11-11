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
# "<status> <body>". Calls to the agent API name the env in agent_env, as an
# agent does; empty names none.
agent_env=dev
api() {
  local method="$1" path="$2" auth="${3:-}" body="${4:-}" args=()
  args=(-sS -o "${work}/body" -w '%{http_code}' -X "$method" -H 'Content-Type: application/json')
  [[ -n "$auth" ]] && args+=(-H "Authorization: Bearer ${auth}")
  [[ "$path" == /agent/* && -n "$agent_env" ]] && args+=(-H "X-K8s-Sealed-Secrets-Sealer-Env: ${agent_env}")
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

# the control plane serves dev and prod: an agent names its env, and only
# that env's registry admits it
[[ "$(agent_env=prod login_status "$registered")" == 401 ]] || die "a dev agent logged in to prod"
[[ "$(agent_env='' login_status "$registered")" == 400 ]] || die "an agent that named no env logged in"
check "an agent logs in only to the env it names and is registered in"

[[ "$(api POST /agent/v1/checkin "" '{}' | cut -d' ' -f1)" == 401 ]] || die "check-in without a session was accepted"
[[ "$(api POST /agent/v1/checkin "$registered" '{}' | cut -d' ' -f1)" == 401 ]] || die "a login token was accepted as a session"
check "check-in requires a session token"

[[ "$(api GET /api/v1/envs/dev/admin/fleet "" | cut -d' ' -f1)" == 401 ]] || die "admin API answered without a token"
check "admin API requires its token"

# --- web UI and sign-in ---
headers="$(curl -sS -D - -o "${work}/index.html" "${control_plane}/fleet")"
grep -qi "^content-security-policy:.*script-src 'self'" <<<"$headers" || die "the UI has no strict content security policy"
grep -qi "^x-frame-options: DENY" <<<"$headers" || die "the UI can be framed"
grep -q 'type="module"' "${work}/index.html" || die "the UI is not served"
check "web UI is served, with a strict content security policy"

[[ "$(api GET /api/v1/envs/dev/fleet "" | cut -d' ' -f1)" == 401 ]] || die "the fleet API answered without sign-in"
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
[[ "$(jq -c '[.user.login, .envs]' <<<"$me")" == '["alice",[{"name":"dev","admin":true},{"name":"prod","admin":true}]]' ]] \
  || die "/me after sign-in: ${me}"
csrf="$(jq -r .csrf_token <<<"$me")"
agents="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/dev/fleet" | jq '.agents | length')"
[[ "$agents" == "$(stack_clusters | wc -l | tr -d ' ')" ]] || die "the signed-in fleet has ${agents} agents"
check "alice (org member, allowed team, admin) signs in to dev and prod and sees the dev fleet"

# dave may sign in but is not an admin: the fleet is closed to him, and he
# sees only whether sealing works
[[ "$(sign_in dave)" == "${control_plane}/fleet" ]] || die "dave could not sign in"
[[ "$(curl -sS -b "${work}/cookies-dave" "${control_plane}/api/v1/auth/me" | jq -c .envs)" == '[{"name":"dev","admin":false}]' ]] \
  || die "dave signed in with more than dev, or as an admin"
[[ "$(curl -sS -o /dev/null -w '%{http_code}' -b "${work}/cookies-dave" "${control_plane}/api/v1/envs/dev/fleet")" == 403 ]] \
  || die "dave, who is not an admin, read the fleet"
status="$(curl -sS -b "${work}/cookies-dave" "${control_plane}/api/v1/envs/dev/status")"
jq -e '(.sealing | IN("ready", "degraded", "unavailable")) and .clusters.total == 3 and (tostring | test("dev-use") | not)' \
  <<<"$status" >/dev/null || die "status for dave: ${status}"
check "dave (not an admin) signs in, cannot read the fleet, and sees whether sealing works"

[[ "$(curl -sS -o /dev/null -w '%{http_code}' -b "${work}/cookies-dave" "${control_plane}/api/v1/envs/prod/status")" == 403 ]] \
  || die "dave, who is not in prod's team, used prod"
status="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/prod/status")"
jq -e '.env == "prod" and .sealing == "unavailable" and .clusters.total == 1' <<<"$status" >/dev/null \
  || die "prod's status for alice: ${status}"
# calls that cost GitHub requests must come from the UI's scripts, which
# send X-Requested-With
page=(-H 'X-Requested-With: XMLHttpRequest')
prod_files="$(curl -sS "${page[@]}" -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/prod/repos/example-org/apps/files")"
jq -e '
  (.files | map(.path)) == ["deploy/billing/sealed-secret.yaml", "deploy/reports/sealed-secret.yaml"]
  and (.files[0].documents | map(.namespace)) == ["billing"]
' <<<"$prod_files" >/dev/null || die "prod's SealedSecrets in example-org/apps: ${prod_files}"
check "prod is for its team only, lists prod's SealedSecrets, and has no agent to seal with here"

# --- repositories, through the GitHub App, limited to alice's own access ---
repos="$(curl -sS "${page[@]}" -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/dev/repos")"
[[ "$(jq -c '[.repositories[] | .full_name + ":" + .access]' <<<"$repos")" == '["example-org/apps:write","example-org/platform:read"]' ]] \
  || die "alice's repositories: ${repos}"
check "alice sees only the repositories she can read, with her access"

files="$(curl -sS "${page[@]}" -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/dev/repos/example-org/apps/files")"
jq -e '
  (.files | map(.path)) == ["deploy/billing/sealed-secret.yaml", "deploy/legacy/sealed-secret.yaml", "deploy/search/sealed-secret.yaml", "deploy/worker/sealed-secret.yaml"]
  and (.files[0].documents | map(.namespace)) == ["dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"]
  and (.files[1].documents[0].problem | test("cluster-wide"))
' <<<"$files" >/dev/null || die "SealedSecret discovery in example-org/apps: ${files}"
check "discovery finds the dev SealedSecrets in example-org/apps, and flags cluster-wide scope"

restricted="$(curl -sS -o /dev/null -w '%{http_code}' "${page[@]}" -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/dev/repos/example-org/restricted/files")"
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
  fleet="$(api GET /api/v1/envs/dev/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
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
  fleet="$(api GET /api/v1/envs/dev/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
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

# --- sealing: alice seals one value into the billing file, which has a dev
# document for each simulated cluster. One agent decrypts it from transit
# and seals it for all three with the env key. ---
[[ "$(sign_in alice)" == "${control_plane}/fleet" ]] || die "alice could not sign in again"
csrf="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/auth/me" | jq -r .csrf_token)"
# as_alice <method> <path> [json body]: prints "<status> <body>"
as_alice() {
  local args=(-sS -o "${work}/body" -w '%{http_code}' -X "$1" -b "${work}/cookies-alice"
    -H 'Content-Type: application/json' -H "X-CSRF-Token: ${csrf}" "${page[@]}")
  [[ -n "${3:-}" ]] && args+=(--data "$3")
  printf '%s %s' "$(curl "${args[@]}" "${control_plane}$2")" "$(/bin/cat "${work}/body")"
}
apps=/api/v1/envs/dev/repos/example-org/apps
out="$(as_alice POST "${apps}/session" "$(jq -nc --arg c "$(jq -r .commit <<<"$files")" '{commit: $c}')")"
[[ "${out%% *}" == 201 ]] || die "alice could not open a session: ${out}"
session="$(jq -r .session.id <<<"${out#* }")"
check "alice opens a session on example-org/apps at the commit she saw"

value="e2e-$(openssl rand -hex 12)"
out="$(as_alice POST "${apps}/session/${session}/seals" \
  "$(jq -nc --arg v "$value" '{path: "deploy/billing/sealed-secret.yaml", key: "api-token", value: $v}')")"
[[ "${out%% *}" == 202 ]] || die "seal request: ${out}"
seal="$(jq -r .id <<<"${out#* }")"
status=""
for _ in $(seq 1 60); do
  out="$(as_alice GET "${apps}/session/${session}/seals/${seal}")"
  status="$(jq -r .status <<<"${out#* }")"
  [[ "$status" == queued || "$status" == sealing ]] || break
  sleep 1
done
[[ "$status" == sealed ]] || die "the seal did not finish: ${out}"
sealer="$(jq -r .agent.id <<<"${out#* }")"
[[ "$(jq -r .fingerprint <<<"${out#* }")" == "$env_key" ]] || die "sealed with a key other than the env key: ${out}"
check "agent ${sealer} seals the value with the env key"

out="$(as_alice GET "${apps}/session")"
jq -e --arg fp "$env_key" '
  .session.changes as $c
  | ($c | length) == 1 and $c[0].key == "api-token" and $c[0].fingerprint == $fp
  and ($c[0].targets | map(.namespace)) == ["dev-use1-blue-apps", "dev-use1-green-apps", "dev-use2-blue-apps"]
  and ([.. | objects | select(has("ciphertext") or has("ciphertexts"))] | length) == 0
' <<<"${out#* }" >/dev/null || die "pending changes: ${out}"
check "the session holds one pending change for the three dev documents, without ciphertexts"

[[ "$(log_events sealer-system sealer-control-plane seal.succeeded | wc -l | tr -d ' ')" == 1 ]] \
  || die "the control plane did not log seal.succeeded once"
[[ -n "$(log_events "${sealer}-sealer" sealer-agent seal.sealed)" ]] || die "agent ${sealer} did not log seal.sealed"
for deploy in sealer-system/sealer-control-plane $(stack_clusters | sed 's|$|-sealer/sealer-agent|'); do
  if kubectl --context "$KUBE_CONTEXT" -n "${deploy%%/*}" logs "deploy/${deploy#*/}" 2>/dev/null | grep -qF -- "$value"; then
    die "the value appears in the log of ${deploy}"
  fi
done
check "the seal is logged by the control plane and the agent, and the value by neither"

# --- region-specific values: db-password differs between use1 and use2.
# Each seal goes only into its region's documents, by an agent there. ---
# seal_value <json body>: requests a seal, waits for it, prints its view
seal_value() {
  local out seal status=""
  out="$(as_alice POST "${apps}/session/${session}/seals" "$1")"
  [[ "${out%% *}" == 202 ]] || { echo "seal request: ${out}" >&2; return 1; }
  seal="$(jq -r .id <<<"${out#* }")"
  for _ in $(seq 1 60); do
    out="$(as_alice GET "${apps}/session/${session}/seals/${seal}")"
    status="$(jq -r .status <<<"${out#* }")"
    [[ "$status" == queued || "$status" == sealing ]] || break
    sleep 1
  done
  [[ "$status" == sealed ]] || { echo "the seal did not finish: ${out}" >&2; return 1; }
  printf '%s' "${out#* }"
}
db_use1="e2e-$(openssl rand -hex 12)"
db_use2="e2e-$(openssl rand -hex 12)"
out="$(seal_value "$(jq -nc --arg v "$db_use1" \
  '{path: "deploy/billing/sealed-secret.yaml", key: "db-password", value: $v, regions: ["use1"]}')")" \
  || die "db-password for use1 was not sealed"
jq -e '.regions == ["use1"] and (.targets | map(.namespace)) == ["dev-use1-blue-apps", "dev-use1-green-apps"]
  and .agent.region == "use1"' <<<"$out" >/dev/null || die "the seal for use1: ${out}"
out="$(seal_value "$(jq -nc --arg v "$db_use2" \
  '{path: "deploy/billing/sealed-secret.yaml", key: "db-password", value: $v, regions: ["use2"]}')")" \
  || die "db-password for use2 was not sealed"
jq -e '.regions == ["use2"] and (.targets | map(.namespace)) == ["dev-use2-blue-apps"]
  and .agent.region == "use2"' <<<"$out" >/dev/null || die "the seal for use2: ${out}"
out="$(as_alice GET "${apps}/session")"
jq -e '.session.changes | map(.key + ":" + ((.regions // []) | join(","))) == ["api-token:", "db-password:use1", "db-password:use2"]' \
  <<<"${out#* }" >/dev/null || die "pending changes after the regional seals: ${out}"
check "db-password is sealed apart for use1 and use2, each by an agent in its region"

code="$(as_alice POST "${apps}/session/${session}/seals" \
  '{"path":"deploy/legacy/sealed-secret.yaml","key":"k","value":"v"}' | cut -d' ' -f1)"
[[ "$code" == 422 ]] || die "a seal into a cluster-wide document answered ${code}"
code="$(as_alice POST /api/v1/envs/dev/repos/example-org/platform/session '{}' | cut -d' ' -f1)"
[[ "$code" == 403 ]] || die "a session on a read-only repository answered ${code}"
code="$(as_alice POST /api/v1/envs/dev/repos/example-org/restricted/session '{}' | cut -d' ' -f1)"
[[ "$code" == 404 ]] || die "a session on a repository alice cannot read answered ${code}"
check "sealing refuses cluster-wide documents and repositories alice cannot write"

# --- pull request: alice opens one with the pending change. Only the dev
# documents' encryptedData changes, and applied to the clusters, every
# controller decrypts the value. ---
out="$(as_alice POST "${apps}/session/${session}/pull-request")"
[[ "${out%% *}" == 201 ]] || die "alice could not open a pull request: ${out}"
pr="$(jq -r .pull_request.number <<<"${out#* }")"
branch="$(jq -r .pull_request.branch <<<"${out#* }")"
[[ "$(as_alice GET "${apps}/session" | cut -d' ' -f2-)" == '{"session":null}' ]] || die "the session outlived its pull request"
check "alice opens pull request #${pr} from ${branch}, which ends the session"

pull="$(curl -sSf "http://localhost:${SEALER_GITHUB_PORT}/_mock/repos/example-org/apps/pulls/${pr}")"
jq -e --arg b "$branch" '
  .head == $b and .base == "main" and (.commits | length) == 1
  and (.files | map(.path)) == ["deploy/billing/sealed-secret.yaml"]
  and (.message | test("Requested-by: alice <1001\\+alice@users.noreply.github.com>"))
  and (.body | test("@alice"))
' <<<"$pull" >/dev/null || die "pull request in GitHub: $(jq -c 'del(.files)' <<<"$pull")"
jq -r '.files[0].before' <<<"$pull" >"${work}/before.yaml"
jq -r '.files[0].after' <<<"$pull" >"${work}/after.yaml"
# the file with the new lines taken out is the file before, with its three
# empty mappings written as block mappings
[[ "$(grep -c '^    api-token: Ag' "${work}/after.yaml")" == 3 ]] || die "the pull request does not seal api-token for three documents"
[[ "$(grep -c '^    db-password: Ag' "${work}/after.yaml")" == 3 ]] || die "the pull request does not seal db-password for three documents"
diff <(sed 's/^  encryptedData: {}$/  encryptedData:/' "${work}/before.yaml") \
  <(grep -Ev '^    (api-token|db-password): ' "${work}/after.yaml") >&2 || die "the pull request changes more than encryptedData"
if grep -qF -- "$(grep -m1 '^    api-token: ' "${work}/after.yaml" | cut -c 16-80)" <<<"$(jq -r '.body + .message + .title' <<<"$pull")"; then
  die "a ciphertext is in the pull request's text"
fi
check "the pull request changes only the dev documents' encryptedData, with nothing secret in its text"

# kubectl prints the file's documents as JSON objects; apply the dev ones
kubectl --context "$KUBE_CONTEXT" create --dry-run=client -o json -f "${work}/after.yaml" \
  | jq -s '{apiVersion: "v1", kind: "List", items: [.[] | if .kind == "List" then .items[] else . end
      | select(.metadata.annotations["k8s-sealed-secrets-sealer/env"] == "dev")]}' \
  | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
for name in $(stack_clusters); do
  got=""
  for _ in $(seq 1 30); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "${name}-apps" get secret billing \
      -o jsonpath='{.data.api-token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 2
  done
  [[ "$got" == "$value" ]] || die "controller ${name} did not unseal the pull request's billing secret"
  case "$name" in
    *-use1-*) want="$db_use1" ;;
    *) want="$db_use2" ;;
  esac
  got="$(kubectl --context "$KUBE_CONTEXT" -n "${name}-apps" get secret billing \
    -o jsonpath='{.data.db-password}' 2>/dev/null | base64 -d 2>/dev/null || true)"
  [[ "$got" == "$want" ]] || die "controller ${name} did not unseal its region's db-password"
done
check "applied to the clusters, the pull request's file unseals to the value in all $(stack_clusters | wc -l | tr -d ' '), and to each region's db-password"

[[ "$(log_events sealer-system sealer-control-plane pr.opened | wc -l | tr -d ' ')" == 1 ]] \
  || die "the control plane did not log pr.opened once"
if kubectl --context "$KUBE_CONTEXT" -n sealer-system logs deploy/sealer-control-plane 2>/dev/null \
  | grep -qF -e "$value" -e "$db_use1" -e "$db_use2"; then
  die "a value appears in the control plane's log"
fi
check "the pull request is logged, and the value is not"

echo "e2e: ${passed} checks passed" >&2
