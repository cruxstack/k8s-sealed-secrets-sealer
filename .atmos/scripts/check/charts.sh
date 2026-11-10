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
  --set dynamodb.table=sealer --set github.org=example-org --set github.oauthClientID=client-id)
agent=(--set controlPlane.url=https://sealer.dev.example.com)

validate deploy/helm/control-plane "${control_plane[@]}"
validate deploy/helm/control-plane "${control_plane[@]}" --set aws.region=us-east-1 \
  --set agentAudience=https://agents.example.com --set dynamodb.endpoint=http://dynamodb:8000 \
  --set dynamodb.createTable=true --set 'aws.stsHosts={sts.us-east-1.amazonaws.com}' \
  --set 'github.allowedTeams={sealers,admins}' --set github.allowInsecure=true \
  --set github.oauthTokenURL=http://mock-github:8080/login/oauth/access_token
validate deploy/helm/agent "${agent[@]}"
validate deploy/helm/agent "${agent[@]}" --set capabilities.keys=true --set capabilities.renewal=true
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

# without their required values, the charts must refuse to render
for chart in deploy/helm/control-plane deploy/helm/agent; do
  if helm template check "$chart" >/dev/null 2>&1; then
    echo "Error: ${chart} renders without its required values" >&2
    exit 1
  fi
done
