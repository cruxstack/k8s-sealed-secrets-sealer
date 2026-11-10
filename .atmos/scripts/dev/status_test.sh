#!/usr/bin/env bash
# Tests status.sh against stand-ins for k3d, kubectl and a control plane
# serving the local stack's envs (dev/stack.yaml) on one URL.
set -euo pipefail

cd "$(dirname "$0")/../../.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

token="$(sed -n 's/^  APP_ADMIN_TOKEN: *//p' dev/k3d/control-plane-secret.yaml)"

/bin/cat >"${work}/k3d" <<'EOF'
#!/usr/bin/env bash
echo "${SEALER_CLUSTER:-sealer} 1/1 0/0 true"
EOF
/bin/cat >"${work}/kubectl" <<'EOF'
#!/usr/bin/env bash
echo "NAMESPACE POD READY STATUS"
EOF
# The control plane, as curl -f sees it: each env's admin API under its own
# path, with the admin token; /api/v1/admin/fleet is not found with several
# envs. STUB_CONTROL_PLANE=down refuses every connection.
/bin/cat >"${work}/curl" <<EOF
#!/usr/bin/env bash
[[ "\${STUB_CONTROL_PLANE:-up}" == up ]] || exit 7
url="" auth=""
while [[ \$# -gt 0 ]]; do
  case "\$1" in
    -H) auth="\$2"; shift ;;
    http*) url="\$1" ;;
  esac
  shift
done
case "\$url" in
  */healthz) exit 0 ;;
  */api/v1/envs/dev/admin/fleet) env=dev ;;
  */api/v1/envs/prod/admin/fleet) env=prod ;;
  *) exit 22 ;;
esac
[[ "\$auth" == "Authorization: Bearer ${token}" ]] || exit 22
if [[ "\$env" == dev ]]; then
  echo '{"env":"dev","env_key":{"fingerprint":"SHA256:devkey"},"agents":[
    {"id":"dev-use1-blue","region":"use1","checked_in":true,"healthy":true,
     "keys":[{"fingerprint":"SHA256:devkey"}],"controller":{"active_fingerprint":"SHA256:devkey"}}]}'
else
  echo '{"env":"prod","env_key":null,"agents":[
    {"id":"prod-use1-blue","region":"use1","checked_in":false,"healthy":false}]}'
fi
EOF
# the table only needs lining up for people; pass it through where column is
# not installed
if ! command -v column >/dev/null; then
  printf '#!/usr/bin/env bash\nexec cat\n' >"${work}/column"
fi
chmod +x "${work}"/*

# expect <name> <control plane up|down> <lines the output must contain...>
expect() {
  local name="$1" state="$2" out line
  shift 2
  out="$(PATH="${work}:${PATH}" STUB_CONTROL_PLANE="$state" SEALER_CLUSTER=sealer \
    bash .atmos/scripts/dev/status.sh 2>&1)" || {
    echo "FAIL - ${name}: status.sh exited with an error: ${out}"
    failures=$((failures + 1))
    return
  }
  for line in "$@"; do
    if ! grep -qF -- "$line" <<<"$out"; then
      echo "FAIL - ${name}: no line with \"${line}\" in:"
      echo "$out"
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok - ${name}"
}

expect "each env's fleet, from its own path" up \
  "Fleet (env dev): env key SHA256:devkey" "dev-use1-blue" \
  "Fleet (env prod): env key none, no cluster has checked in" "prod-use1-blue"
expect "a control plane that is not running" down \
  "Fleet: the control plane is not reachable"

if [[ "$failures" -gt 0 ]]; then
  echo "${failures} status test(s) failed" >&2
  exit 1
fi
