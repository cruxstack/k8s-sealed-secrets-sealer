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
cluster_pid=""
cleanup() {
  local status=$?
  for pid in "${port_forward_pids[@]}"; do kill "$pid" 2>/dev/null; done
  # a build that failed while the cluster was still coming up: let it
  # finish, so it can be deleted
  [[ -n "$cluster_pid" ]] && wait "$cluster_pid" 2>/dev/null
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

# the cluster comes up while the charts, the UI and the binaries are made
ensure_cluster >"${work}/cluster.log" 2>&1 &
cluster_pid=$!
pull_charts
build_web
build_binaries
if ! wait "$cluster_pid"; then
  cluster_pid=""
  /bin/cat "${work}/cluster.log" >&2
  die "could not create the cluster ${SEALER_CLUSTER}"
fi
cluster_pid=""
/bin/cat "${work}/cluster.log" >&2
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
for _ in $(seq 1 120); do
  fleet="$(api GET /api/v1/envs/dev/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
  healthy="$(jq '[.agents[] | select(.healthy)] | length' <<<"$fleet" 2>/dev/null || echo 0)"
  [[ "$healthy" == "$expected" ]] && break
  sleep 1
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
for _ in $(seq 1 240); do
  fleet="$(api GET /api/v1/envs/dev/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-)"
  synced "$fleet" && break
  sleep 1
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
  for _ in $(seq 1 60); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "$apps_ns" get secret e2e-roundtrip \
      -o jsonpath='{.data.value}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 1
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
  # read the log first: under pipefail, grep -q stopping at a match would
  # fail the pipeline (SIGPIPE) and hide the very leak it found
  log="$(kubectl --context "$KUBE_CONTEXT" -n "${deploy%%/*}" logs "deploy/${deploy#*/}" 2>/dev/null || true)"
  if grep -qF -- "$value" <<<"$log"; then
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
  for _ in $(seq 1 60); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "${name}-apps" get secret billing \
      -o jsonpath='{.data.api-token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 1
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
log="$(kubectl --context "$KUBE_CONTEXT" -n sealer-system logs deploy/sealer-control-plane 2>/dev/null || true)"
if grep -qF -e "$value" -e "$db_use1" -e "$db_use2" <<<"$log"; then
  die "a value appears in the control plane's log"
fi
check "the pull request is logged, and the value is not"

# --- key references and deletion: every agent counts the values in the
# SealedSecrets its controller watches by the key that sealed them. A key
# no value uses is revoked, deleted once every cluster counted since, and
# removed from every cluster; reinstated, it comes back from escrow. ---
fleet_now() { api GET /api/v1/envs/dev/admin/fleet "$LOCAL_ADMIN_TOKEN" | cut -d' ' -f2-; }

# each cluster holds the round-trip SealedSecret (one value) and billing
# (api-token and db-password), all sealed with the env key, in the one apps
# namespace its controller watches besides its own
counted() {
  jq -e --argjson n "$expected" --arg fp "$env_key" '
    ([.agents[] | select(.key_usage != null and .key_usage.error == null and .key_usage.unmatched == 0
      and .key_usage.namespaces == [.id + "-apps", .id + "-sealed-secrets"])] | length) == $n
    and (.keys[] | select(.fingerprint == $fp) | .references
      | (.uncounted | length) == 0 and (.clusters | length) == $n
      and ([.clusters[] | select(.values == 3 and .sealed_secrets == 2)] | length) == $n)
  ' <<<"$1" >/dev/null 2>&1
}
for _ in $(seq 1 90); do
  fleet="$(fleet_now)"
  counted "$fleet" && break
  sleep 1
done
counted "$fleet" || die "the clusters did not count the env key's values: $(jq -c --arg fp "$env_key" '{usage: [.agents[] | {id, key_usage}], references: (.keys[] | select(.fingerprint == $fp) | .references)}' <<<"$fleet")"
check "every cluster counts its SealedSecrets: the env key seals 3 values in 2 SealedSecrets in each"

# key_fingerprints <cluster>: the fingerprints of every key Secret in its
# controller's namespace, under any value of the key label, computed from
# each certificate as the controller does (SSH SHA-256 of the public key)
key_fingerprints() {
  local cert
  for cert in $(kubectl --context "$KUBE_CONTEXT" -n "${1}-sealed-secrets" get secrets \
    -l sealedsecrets.bitnami.com/sealed-secrets-key -o json | jq -r '.items[].data["tls.crt"]'); do
    base64 -d <<<"$cert" | openssl x509 -pubkey -noout \
      | ssh-keygen -i -m PKCS8 -f /dev/stdin | ssh-keygen -lf - | awk '{print $2}'
  done
}
# key_in_every_cluster <fingerprint> <yes|no>: whether every cluster holds
# it (yes) or none does (no)
key_in_every_cluster() {
  local name fps
  for name in $(stack_clusters); do
    # not piped into grep -q: under pipefail, its early exit fails the
    # pipeline whenever the key is not the last one listed
    fps="$(key_fingerprints "$name")"
    if grep -qxF -- "$1" <<<"$fps"; then
      [[ "$2" == yes ]] || return 1
    else
      [[ "$2" == no ]] || return 1
    fi
  done
}

# a key every cluster counted no value of; the clusters' own keys, made
# together, are older keys beside the env key
unused="$(jq -r --arg fp "$env_key" '[.keys[] | select(.fingerprint != $fp and .status == "active"
  and .references.values == 0 and (.references.clusters | length) > 0)][0].fingerprint // empty' <<<"$fleet")"
[[ -n "$unused" ]] || die "no key without references besides the env key: $(jq -c '[.keys[] | {fingerprint, status, references}]' <<<"$fleet")"
key_in_every_cluster "$unused" yes || die "the key ${unused} is not in every cluster's key Secrets"
key_path="/api/v1/envs/dev/keys/$(tr '+/' '-_' <<<"$unused")"

out="$(as_alice POST "${key_path}/delete")"
[[ "${out%% *}" == 409 && "$(jq -r .error <<<"${out#* }")" == "Revoke the key first." ]] || die "delete of an active key: ${out}"
[[ "$(jq -r --arg fp "$unused" '.keys[] | select(.fingerprint == $fp) | .delete_blocked' <<<"$(fleet_now)")" == "Revoke the key first." ]] \
  || die "the fleet does not say why the active key cannot be deleted"
check "an active key cannot be deleted (${unused})"

out="$(as_alice POST "${key_path}/revoke")"
[[ "${out%% *}" == 200 && "$(jq -r .status <<<"${out#* }")" == revoked ]] || die "revoke: ${out}"
# the counts so far came in before the revocation
out="$(as_alice POST "${key_path}/delete")"
[[ "${out%% *}" == 409 && "$(jq -r .error <<<"${out#* }")" == "Waiting for "* ]] || die "delete right after revoking: ${out}"
check "a revoked key cannot be deleted until every cluster counted it since"

# each agent counts and checks in every 5 seconds
started=$SECONDS
for _ in $(seq 1 120); do
  out="$(as_alice POST "${key_path}/delete")"
  [[ "${out%% *}" == 409 ]] || break
  sleep 1
done
[[ "${out%% *}" == 200 ]] || die "delete after the clusters counted: ${out}"
jq -e '.status == "deleted" and .status_by == "alice" and (.purge_at | type) == "string"' <<<"${out#* }" >/dev/null \
  || die "the deleted key's status: ${out}"
check "once every cluster counted it since the revocation, alice deletes it ($((SECONDS - started))s)"

started=$SECONDS
removed=""
for _ in $(seq 1 120); do
  fleet="$(fleet_now)"
  if jq -e --arg fp "$unused" '.keys[] | select(.fingerprint == $fp) | .status == "deleted" and (.holders | length) == 0' \
    <<<"$fleet" >/dev/null 2>&1 && key_in_every_cluster "$unused" no; then
    removed=yes
    break
  fi
  sleep 1
done
[[ -n "$removed" ]] || die "the deleted key was not removed from every cluster: $(jq -c --arg fp "$unused" '.keys[] | select(.fingerprint == $fp)' <<<"$fleet")"
[[ "$(log_events sealer-system sealer-control-plane key.removed | wc -l | tr -d ' ')" == "$expected" ]] \
  || die "the control plane did not log key.removed once per cluster"
check "every agent removes the deleted key from its cluster's key Secrets, and the fleet shows it held by none ($((SECONDS - started))s)"

out="$(as_alice POST "${key_path}/reinstate")"
[[ "${out%% *}" == 200 && "$(jq -r .status <<<"${out#* }")" == active ]] || die "reinstate: ${out}"
started=$SECONDS
for _ in $(seq 1 180); do
  fleet="$(fleet_now)"
  synced "$fleet" && key_in_every_cluster "$unused" yes && break
  sleep 1
done
synced "$fleet" && key_in_every_cluster "$unused" yes \
  || die "the reinstated key did not come back to every cluster: $(jq -c --arg fp "$unused" '.keys[] | select(.fingerprint == $fp)' <<<"$fleet")"
[[ "$(jq -r .env_key.fingerprint <<<"$fleet")" == "$env_key" ]] || die "the env key changed: $(jq -c .env_key <<<"$fleet")"
check "reinstated, the key is restored to every cluster from escrow, and the env key is unchanged ($((SECONDS - started))s)"

# --- resealing: values sealed with an older key move onto the env key
# without being decrypted. alice reseals a file in a session; a schedule
# reseals the repository and opens one pull request; a second run skips the
# repository while that pull request is open; closed in GitHub, the tick
# sees it so. The control plane ticks every second here, and checks an open
# reseal pull request about every 15. ---
mock="http://localhost:${SEALER_GITHUB_PORT}"
fleet="$(fleet_now)"
# an older key every cluster holds: one of the keys the clusters made
# together, not the env key, preferring the one not deleted above
old_key="$(jq -r --arg env "$env_key" --arg unused "$unused" --argjson n "$expected" '
  [.keys[] | select(.fingerprint != $env and .status == "active" and (.holders | length) == $n)]
  | sort_by(.fingerprint == $unused) | .[0].fingerprint // empty' <<<"$fleet")"
[[ -n "$old_key" ]] || die "no older key every cluster holds: $(jq -c '[.keys[] | {fingerprint, status, holders}]' <<<"$fleet")"
jq -e --argjson n "$expected" '[.agents[] | select((.capabilities // []) | index("reseal"))] | length == $n' <<<"$fleet" >/dev/null \
  || die "not every agent reports the reseal capability: $(jq -c '[.agents[] | {id, capabilities}]' <<<"$fleet")"
# cert_of <fingerprint> <file>: a key's certificate, from a cluster that
# restored it from escrow (restored key Secrets name their fingerprint)
cert_of() {
  local name
  for name in $(stack_clusters); do
    kubectl --context "$KUBE_CONTEXT" -n "${name}-sealed-secrets" get secrets \
      -l sealedsecrets.bitnami.com/sealed-secrets-key -o json \
      | jq -r --arg fp "$1" '.items[] | select(.metadata.annotations["sealer.cruxstack.io/fingerprint"] == $fp)
          | .data["tls.crt"]' | head -n 1 | base64 -d >"$2" 2>/dev/null || true
    [[ -s "$2" ]] && return 0
  done
  return 1
}
cert_of "$old_key" "${work}/old-key.pem" || die "no cluster holds a restored copy of ${old_key}"
# seal_raw <cert> <namespace> <value>: a strict value of the reseal
# SealedSecret in namespace, as kubeseal seals it
seal_raw() {
  printf '%s' "$3" | kubeseal --raw --cert "$1" --scope strict --namespace "$2" --name reseal --from-file=/dev/stdin
}
reseal_path=deploy/reseal/sealed-secret.yaml
old_prefix="e2e-old-$(openssl rand -hex 8)"
for name in $(stack_clusters); do
  printf -- '---\napiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: reseal\n  namespace: %s\n  annotations:\n    k8s-sealed-secrets-sealer/env: dev\nspec:\n  encryptedData:\n    current-token: %s\n    old-token: %s\n' \
    "${name}-apps" "$(seal_raw "${work}/env-key.pem" "${name}-apps" "current-${name}")" \
    "$(seal_raw "${work}/old-key.pem" "${name}-apps" "${old_prefix}-${name}")"
done >"${work}/reseal.yaml"
curl -sSf -o /dev/null -X POST -H 'Content-Type: application/json' \
  --data "$(jq -n --rawfile c "${work}/reseal.yaml" --arg p "$reseal_path" '{branch: "main", files: {($p): $c}}')" \
  "${mock}/_mock/repos/example-org/apps/commits" || die "could not push the reseal fixture to the mock"
check "a file with a value sealed with an older key (${old_key}) is pushed to example-org/apps"

# an agent reseals only onto the key its controller seals with: the env
# key's own cluster's controller does, the clusters' keys being made in the
# same second
status="$(curl -sS -b "${work}/cookies-alice" "${control_plane}/api/v1/envs/dev/status")"
jq -e '.can_reseal' <<<"$status" >/dev/null || die "the env cannot reseal: ${status}"
head_commit="$(curl -sS "${page[@]}" -b "${work}/cookies-alice" "${control_plane}${apps}/files" | jq -r .commit)"
out="$(as_alice POST "${apps}/session" "$(jq -nc --arg c "$head_commit" '{commit: $c}')")"
[[ "${out%% *}" == 201 ]] || die "alice could not open a session for the reseal: ${out}"
session="$(jq -r .session.id <<<"${out#* }")"
started=$SECONDS
out="$(as_alice POST "${apps}/session/${session}/reseals" "$(jq -nc --arg p "$reseal_path" '{path: $p}')")"
[[ "${out%% *}" == 202 ]] || die "reseal request: ${out}"
reseal="$(jq -r .id <<<"${out#* }")"
status=""
for _ in $(seq 1 60); do
  out="$(as_alice GET "${apps}/session/${session}/reseals/${reseal}")"
  status="$(jq -r .status <<<"${out#* }")"
  [[ "$status" == queued || "$status" == resealing ]] || break
  sleep 1
done
n="$(stack_clusters | wc -l | tr -d ' ')"
jq -e --argjson n "$n" '.status == "done" and .values == {total: (2 * $n), resealed: $n, current: $n, failed: 0, pending: 0}
  and (.change_ids | length) == 1' <<<"${out#* }" >/dev/null || die "the reseal did not finish as expected: ${out}"
out="$(as_alice GET "${apps}/session")"
jq -e --arg env "$env_key" --arg old "$old_key" --argjson n "$n" '
  .session.changes as $c
  | ($c | length) == 1 and $c[0].kind == "reseal" and $c[0].key == "old-token" and ($c[0].targets | length) == $n
  and $c[0].fingerprint == $env and $c[0].resealed_from == [$old]
  and ([.. | objects | select(has("ciphertext") or has("ciphertexts"))] | length) == 0
' <<<"${out#* }" >/dev/null || die "pending changes after the reseal: ${out}"
check "alice reseals the file: old-token moves to the env key in ${n} documents, current-token is current ($((SECONDS - started))s)"

out="$(as_alice POST "${apps}/session/${session}/pull-request")"
[[ "${out%% *}" == 201 ]] || die "alice could not open the reseal pull request: ${out}"
manual_pr="$(jq -r .pull_request.number <<<"${out#* }")"
pull="$(curl -sSf "${mock}/_mock/repos/example-org/apps/pulls/${manual_pr}")"
jq -e --arg p "$reseal_path" --argjson n "$n" '(.files | map(.path)) == [$p] and (.title | startswith("Reseal \($n) values"))
  and (.body | test("does not rotate"))' \
  <<<"$pull" >/dev/null || die "the reseal pull request: $(jq -c 'del(.files)' <<<"$pull")"
jq -r '.files[0].before' <<<"$pull" >"${work}/reseal-before.yaml"
jq -r '.files[0].after' <<<"$pull" >"${work}/reseal-after.yaml"
diff <(grep -v '^    old-token: ' "${work}/reseal-before.yaml") <(grep -v '^    old-token: ' "${work}/reseal-after.yaml") >&2 \
  || die "the reseal pull request changes more than old-token"
[[ "$(grep -c '^    old-token: ' "${work}/reseal-after.yaml")" == "$n" ]] \
  && [[ -z "$(comm -12 <(grep '^    old-token: ' "${work}/reseal-before.yaml" | sort) <(grep '^    old-token: ' "${work}/reseal-after.yaml" | sort))" ]] \
  || die "the reseal pull request does not reseal old-token in every document"
check "the pull request (#${manual_pr}) changes only old-token's encryptedData, and says resealing does not rotate values"

# applied, every controller decrypts the resealed value to what it was, and
# counts it under the env key: two values and one SealedSecret more than
# it counted before, and nothing more under the older key
refs_before="$(fleet_now)"
env_before="$(jq -c --arg fp "$env_key" '[.keys[] | select(.fingerprint == $fp) | .references.clusters[]
  | {key: .agent, value: {values, sealed_secrets}}] | from_entries' <<<"$refs_before")"
old_before="$(jq --arg fp "$old_key" '[.keys[] | select(.fingerprint == $fp) | .references.values][0] // 0' <<<"$refs_before")"
kubectl --context "$KUBE_CONTEXT" create --dry-run=client -o json -f "${work}/reseal-after.yaml" \
  | jq -s '{apiVersion: "v1", kind: "List", items: [.[] | if .kind == "List" then .items[] else . end]}' \
  | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
for name in $(stack_clusters); do
  got=""
  for _ in $(seq 1 60); do
    got="$(kubectl --context "$KUBE_CONTEXT" -n "${name}-apps" get secret reseal \
      -o jsonpath='{.data.old-token}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [[ -n "$got" ]] && break
    sleep 1
  done
  [[ "$got" == "${old_prefix}-${name}" ]] || die "controller ${name} did not unseal the resealed old-token"
done
started=$SECONDS
moved() {
  jq -e --argjson n "$expected" --arg env "$env_key" --arg old "$old_key" \
    --argjson before "$env_before" --argjson old_before "$old_before" '
    ([.keys[] | select(.fingerprint == $env) | .references.clusters[]
      | select(.values == (($before[.agent].values // 0) + 2)
        and .sealed_secrets == (($before[.agent].sealed_secrets // 0) + 1))] | length) == $n
    and ([.keys[] | select(.fingerprint == $old) | .references.values][0] // 0) == $old_before
  ' <<<"$1" >/dev/null 2>&1
}
for _ in $(seq 1 90); do
  fleet="$(fleet_now)"
  moved "$fleet" && break
  sleep 1
done
moved "$fleet" || die "the clusters do not count the resealed value under the env key: $(jq -c --arg env "$env_key" --arg old "$old_key" '[.keys[] | select(.fingerprint == $env or .fingerprint == $old) | {fingerprint, references}]' <<<"$fleet")"
check "applied, every controller unseals the resealed value, and counts it under the env key, none under ${old_key} ($((SECONDS - started))s)"

# --- a schedule for example-org/apps, run now: the run opens one pull
# request with the value main still holds on the older key ---
out="$(as_alice POST /api/v1/envs/dev/reseal/schedules '{"name":"e2e","repos":["example-org/apps"],"interval_days":75}')"
[[ "${out%% *}" == 201 ]] || die "alice could not create a schedule: ${out}"
schedule="$(jq -r .id <<<"${out#* }")"
jq -e '.enabled and .interval_days == 75 and (.next_run_at | type) == "string"' <<<"${out#* }" >/dev/null || die "schedule: ${out}"
# run_now: starts a run of the schedule and waits for it to finish, up to
# three minutes; prints the run with its repositories
run_now() {
  local out run status=""
  out="$(as_alice POST "/api/v1/envs/dev/reseal/schedules/${schedule}/run")"
  [[ "${out%% *}" == 202 ]] || { echo "run now: ${out}" >&2; return 1; }
  run="$(jq -r .id <<<"${out#* }")"
  for _ in $(seq 1 180); do
    out="$(as_alice GET "/api/v1/envs/dev/reseal/runs/${run}")"
    status="$(jq -r .status <<<"${out#* }")"
    [[ "$status" == queued || "$status" == running ]] || break
    sleep 1
  done
  printf '%s' "${out#* }"
}
started=$SECONDS
run="$(run_now)" || die "the run did not start"
jq -e --argjson n "$n" '.status == "succeeded" and .repos.total == 1 and .repos.hidden == 0 and .pull_requests == 1
  and .repositories[0].repo == "example-org/apps" and .repositories[0].status == "opened"
  and .repositories[0].values.resealed == $n' <<<"$run" >/dev/null || die "the run: ${run}"
run_id="$(jq -r .id <<<"$run")"
run_pr="$(jq -r '.repositories[0].pull_request.number' <<<"$run")"
pull="$(curl -sSf "${mock}/_mock/repos/example-org/apps/pulls/${run_pr}")"
jq -e --arg p "$reseal_path" --arg b "sealer/dev/reseal-$(tr '[:upper:]' '[:lower:]' <<<"$run_id")" '
  .head == $b and (.files | map(.path)) == [$p] and (.message | test("Requested-by: alice <1001\\+alice@users.noreply.github.com>"))
' <<<"$pull" >/dev/null || die "the run's pull request: $(jq -c 'del(.files)' <<<"$pull")"
diff <(jq -r '.files[0].before' <<<"$pull" | grep -v '^    old-token: ') <(jq -r '.files[0].after' <<<"$pull" | grep -v '^    old-token: ') >&2 \
  || die "the run's pull request changes more than old-token"
prs="$(as_alice GET /api/v1/envs/dev/reseal/pull-requests | cut -d' ' -f2-)"
jq -e --argjson pr "$run_pr" --argjson manual "$manual_pr" --arg run "$run_id" '
  .hidden == 0
  and ([.pull_requests[] | select(.number == $pr and .source == "schedule" and .run_id == $run and .state == "open")] | length) == 1
  and ([.pull_requests[] | select(.number == $manual and .source == "session" and .requested_by == "alice")] | length) == 1
' <<<"$prs" >/dev/null || die "reseal pull requests: ${prs}"
check "run now opens one pull request (#${run_pr}) changing only old-token, listed with the session's as open ($((SECONDS - started))s)"

started=$SECONDS
run="$(run_now)" || die "the second run did not start"
jq -e --argjson pr "$run_pr" '.status == "succeeded" and .pull_requests == 0 and .repositories[0].status == "skipped"
  and .repositories[0].pull_request.number == $pr' <<<"$run" >/dev/null || die "the second run: ${run}"
check "a second run skips example-org/apps while its reseal pull request is open ($((SECONDS - started))s)"

curl -sSf -o /dev/null -X POST "${mock}/_mock/repos/example-org/apps/pulls/${run_pr}/close" || die "could not close #${run_pr} in the mock"
started=$SECONDS
closed=""
for _ in $(seq 1 150); do
  prs="$(as_alice GET '/api/v1/envs/dev/reseal/pull-requests?state=closed' | cut -d' ' -f2-)"
  if jq -e --argjson pr "$run_pr" '[.pull_requests[] | select(.number == $pr and .state == "closed")] | length == 1' <<<"$prs" >/dev/null 2>&1; then
    closed=yes
    break
  fi
  sleep 1
done
[[ -n "$closed" ]] || die "the tick did not see #${run_pr} closed: ${prs}"
check "closed in GitHub, the tick marks the reseal pull request closed ($((SECONDS - started))s)"

for event in reseal.requested reseal.schedule_created reseal.run_started reseal.run_finished reseal.pr_opened reseal.pr_closed; do
  [[ -n "$(log_events sealer-system sealer-control-plane "$event")" ]] || die "the control plane did not log ${event}"
done
done_logged=""
for name in $(stack_clusters); do
  [[ -n "$(log_events "${name}-sealer" sealer-agent reseal.done)" ]] && done_logged=yes
done
[[ -n "$done_logged" ]] || die "no agent logged reseal.done"
for deploy in sealer-system/sealer-control-plane $(stack_clusters | sed 's|$|-sealer/sealer-agent|'); do
  log="$(kubectl --context "$KUBE_CONTEXT" -n "${deploy%%/*}" logs "deploy/${deploy#*/}" 2>/dev/null || true)"
  if grep -qF -- "$old_prefix" <<<"$log"; then
    die "a resealed value appears in the log of ${deploy}"
  fi
done
check "resealing is logged by the control plane and the agents, and no value is"

# dave is no admin: schedules and resealing a file are closed to him
dave_csrf="$(curl -sS -b "${work}/cookies-dave" "${control_plane}/api/v1/auth/me" | jq -r .csrf_token)"
as_dave() {
  local args=(-sS -o /dev/null -w '%{http_code}' -X "$1" -b "${work}/cookies-dave" -H 'Content-Type: application/json'
    -H "X-CSRF-Token: ${dave_csrf}" "${page[@]}")
  [[ -n "${3:-}" ]] && args+=(--data "$3")
  curl "${args[@]}" "${control_plane}$2"
}
[[ "$(as_dave GET /api/v1/envs/dev/reseal/schedules)" == 403 ]] || die "dave read the schedules"
[[ "$(as_dave POST /api/v1/envs/dev/reseal/schedules '{"name":"x","repos":["example-org/apps"],"interval_days":1}')" == 403 ]] \
  || die "dave created a schedule"
[[ "$(as_dave POST "${apps}/session/${session}/reseals" "$(jq -nc --arg p "$reseal_path" '{path: $p}')")" == 403 ]] \
  || die "dave resealed a file"
check "dave (not an admin) gets 403 on schedules and on resealing a file"

# leave the stack as it was for --keep: the reseal SealedSecrets out of the
# clusters, the schedule deleted, alice's reseal pull request closed
for name in $(stack_clusters); do
  kubectl --context "$KUBE_CONTEXT" -n "${name}-apps" delete sealedsecret reseal --ignore-not-found >/dev/null
done
[[ "$(as_alice DELETE "/api/v1/envs/dev/reseal/schedules/${schedule}" | cut -d' ' -f1)" == 204 ]] \
  || die "the e2e schedule could not be deleted"
curl -sSf -o /dev/null -X POST "${mock}/_mock/repos/example-org/apps/pulls/${manual_pr}/close" \
  || die "could not close #${manual_pr} in the mock"
check "the reseal checks clean up after themselves"

echo "e2e: ${passed} checks passed" >&2
