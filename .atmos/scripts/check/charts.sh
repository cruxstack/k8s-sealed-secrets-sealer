#!/usr/bin/env bash
# Lints the Helm charts and validates what they render against the Kubernetes
# schemas, with default values and with every option that adds objects on.
set -euo pipefail

schemas=".tools/kubeconform-schemas"
mkdir -p "$schemas"

validate() {
  local chart="$1"
  shift
  echo "+ helm lint ${chart} $*" >&2
  helm lint --strict "$chart" "$@" >&2
  echo "+ helm template ${chart} $* | kubeconform" >&2
  helm template check "$chart" --namespace check "$@" \
    | kubeconform -strict -summary -cache "$schemas" -kubernetes-version 1.35.0 -
}

# the minimum each chart requires
control_plane=(--set env=dev --set publicURL=https://sealer.dev.example.com
  --set registry.configMapName=sealer-registry --set existingSecret=sealer
  --set dynamodb.table=sealer --set github.org=example-org --set github.oauthClientID=client-id
  --set github.appID=12345 --set kms.transitKeyId=alias/sealer-transit)
agent=(--set controlPlane.url=https://sealer.dev.example.com --set env=dev --set kms.transitKeyId=alias/sealer-transit)

validate deploy/helm/control-plane "${control_plane[@]}"
validate deploy/helm/control-plane "${control_plane[@]}" --set aws.region=us-east-1 \
  --set agentAudience=https://agents.example.com --set dynamodb.endpoint=http://dynamodb:8000 \
  --set dynamodb.createTable=true --set 'aws.stsHosts={sts.us-east-1.amazonaws.com}' \
  --set 'github.allowedTeams={sealers,admins}' --set 'github.adminTeams={admins}' --set github.allowInsecure=true \
  --set github.oauthTokenURL=http://mock-github:8080/login/oauth/access_token \
  --set github.installationID=777 --set 'discovery.fileGlobs={*.sealed.yaml,secrets/*/*.yaml}' \
  --set kms.region=us-east-1 --set kms.endpoint=http://local-kms:8080
# several envs on one URL: APP_ENVS instead of the one env's settings
envs=(--set publicURL=https://sealer.example.com --set registry.configMapName=sealer-registry
  --set existingSecret=sealer --set github.org=example-org --set github.oauthClientID=client-id
  --set github.appID=12345
  --set 'envs[0].name=dev' --set 'envs[0].dynamodbTable=sealer-dev' --set 'envs[0].kmsTransitKeyId=alias/dev'
  --set 'envs[1].name=prod' --set 'envs[1].dynamodbTable=sealer-prod' --set 'envs[1].kmsTransitKeyId=alias/prod'
  --set 'envs[1].allowedTeams={prod-sealers}')
validate deploy/helm/control-plane "${envs[@]}"
rendered="$(helm template check deploy/helm/control-plane "${envs[@]}")"
if ! grep -q 'name: APP_ENVS' <<<"$rendered" || grep -qE 'name: APP_(ENV_NAME|DYNAMODB_TABLE|KMS_TRANSIT_KEY_ID)$' <<<"$rendered"; then
  echo "Error: the control plane chart does not render envs as APP_ENVS alone" >&2
  exit 1
fi
validate deploy/helm/agent "${agent[@]}"
validate deploy/helm/agent "${agent[@]}" --set capabilities.keys=true --set capabilities.renewal=true \
  --set kms.escrowKeyId=alias/sealer-escrow --set kms.region=us-east-1 --set kms.endpoint=http://local-kms:8080
keys=(--set capabilities.keys=true --set kms.escrowKeyId=alias/sealer-escrow)
validate deploy/helm/agent "${agent[@]}" "${keys[@]}" --set capabilities.cleanup=true --set keyUsageInterval=30s
# cleanup reads SealedSecrets everywhere, by a ClusterRole whose name is
# unique per release and namespace, deletes Secrets in the controller's
# namespace, and gets its interval; without it nothing is cluster-wide
cleanup="$(helm template check deploy/helm/agent "${agent[@]}" "${keys[@]}" --set capabilities.cleanup=true --namespace blue-sealer)"
if ! grep -q 'name: blue-sealer-check-sealedsecrets' <<<"$cleanup" || ! grep -q 'kind: ClusterRoleBinding' <<<"$cleanup" ||
  ! grep -A1 'resources: \["sealedsecrets"\]' <<<"$cleanup" | grep -q 'verbs: \["list"\]' ||
  ! grep -q 'verbs: \["delete"\]' <<<"$cleanup" || ! grep -q 'name: APP_KEY_USAGE_INTERVAL' <<<"$cleanup"; then
  echo "Error: the agent chart does not grant cleanup what it needs" >&2
  exit 1
fi
if helm template check deploy/helm/agent "${agent[@]}" "${keys[@]}" | grep -qE 'kind: ClusterRole|verbs: \["delete"\]|APP_KEY_USAGE_INTERVAL'; then
  echo "Error: the agent chart grants cleanup's permissions without it" >&2
  exit 1
fi
# the agent keeps its heap under its memory limit, when it has one
if ! helm template check deploy/helm/agent "${agent[@]}" | grep -A4 'name: APP_MEMORY_LIMIT' | grep -q 'resource: limits.memory' ||
  helm template check deploy/helm/agent "${agent[@]}" --set resources.limits.memory=null | grep -q 'APP_MEMORY_LIMIT'; then
  echo "Error: the agent chart does not pass its memory limit, or passes one it does not have" >&2
  exit 1
fi
# cleanup needs keys
if helm template check deploy/helm/agent "${agent[@]}" --set capabilities.cleanup=true >/dev/null 2>&1; then
  echo "Error: the agent chart enables cleanup without keys" >&2
  exit 1
fi
# reseal needs keys, and adds no permission of its own
validate deploy/helm/agent "${agent[@]}" "${keys[@]}" --set capabilities.reseal=true
if helm template check deploy/helm/agent "${agent[@]}" --set capabilities.reseal=true >/dev/null 2>&1; then
  echo "Error: the agent chart enables reseal without keys" >&2
  exit 1
fi
# the same objects as keys alone, but for the capability it names
with_reseal="$(helm template check deploy/helm/agent "${agent[@]}" "${keys[@]}" --set capabilities.reseal=true)"
without="$(helm template check deploy/helm/agent "${agent[@]}" "${keys[@]}")"
if ! grep -A1 'name: APP_CAPABILITIES' <<<"$with_reseal" | grep -q '"keys,reseal,seal"' ||
  [[ "$(sed 's/"keys,reseal,seal"/"keys,seal"/' <<<"$with_reseal")" != "$without" ]]; then
  echo "Error: the agent chart does not turn on reseal alone, or grants it more" >&2
  exit 1
fi
validate deploy/helm/agent "${agent[@]}" --set identity.mode=aws-sts --set aws.region=us-east-1 \
  --set 'serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::123456789012:role/agent'

# aws-sts mounts no projected token; an unknown identity mode is refused
if helm template check deploy/helm/agent "${agent[@]}" --set identity.mode=aws-sts | grep -q serviceAccountToken; then
  echo "Error: the agent chart mounts a projected token in aws-sts mode" >&2
  exit 1
fi
if helm template check deploy/helm/agent "${agent[@]}" --set identity.mode=password >/dev/null 2>&1; then
  echo "Error: the agent chart accepts an unknown identity mode" >&2
  exit 1
fi
# the keys capability needs the escrow key, the seal capability the transit key
if helm template check deploy/helm/agent "${agent[@]}" --set capabilities.keys=true >/dev/null 2>&1; then
  echo "Error: the agent chart enables keys without an escrow key" >&2
  exit 1
fi
if helm template check deploy/helm/agent "${agent[@]}" --set kms.transitKeyId= >/dev/null 2>&1; then
  echo "Error: the agent chart enables seal without a transit key" >&2
  exit 1
fi
# an agent that does not seal needs no transit key
validate deploy/helm/agent "${agent[@]}" --set kms.transitKeyId= --set capabilities.seal=false \
  --set capabilities.renewal=true
# with every capability off the agent runs with none, not the default seal
validate deploy/helm/agent "${agent[@]}" --set kms.transitKeyId= --set capabilities.seal=false
if ! helm template check deploy/helm/agent "${agent[@]}" --set capabilities.seal=false \
  | grep -A1 'name: APP_CAPABILITIES' | grep -q '"none"'; then
  echo "Error: the agent chart does not render no capabilities as none" >&2
  exit 1
fi
# the control plane compares the token audience with its URL, which has no
# trailing slash
if helm template check deploy/helm/agent "${agent[@]}" --set controlPlane.url=https://sealer.dev.example.com/ \
  | grep -q 'sealer.dev.example.com/"'; then
  echo "Error: the agent chart keeps a trailing slash on controlPlane.url" >&2
  exit 1
fi
# two pods of one agent must never run at once
if ! helm template check deploy/helm/agent "${agent[@]}" | grep -q 'type: Recreate'; then
  echo "Error: the agent Deployment does not use the Recreate strategy" >&2
  exit 1
fi
# keys deletes pods and reads every Secret in the controller's namespace, so
# not in kube-system; seal alone may run there
if helm template check deploy/helm/agent "${agent[@]}" --set capabilities.keys=true \
  --set kms.escrowKeyId=alias/sealer-escrow --set controller.namespace=kube-system >/dev/null 2>&1; then
  echo "Error: the agent chart enables keys with the controller in kube-system" >&2
  exit 1
fi
validate deploy/helm/agent "${agent[@]}" --set controller.namespace=kube-system
# only renewal may patch the controller Deployment
if helm template check deploy/helm/agent "${agent[@]}" --set capabilities.keys=true \
  --set kms.escrowKeyId=alias/sealer-escrow | grep -q '"patch"'; then
  echo "Error: the agent chart lets the keys capability patch the controller Deployment" >&2
  exit 1
fi

# without their required values, the charts must refuse to render
for chart in deploy/helm/control-plane deploy/helm/agent; do
  if helm template check "$chart" >/dev/null 2>&1; then
    echo "Error: ${chart} renders without its required values" >&2
    exit 1
  fi
done
