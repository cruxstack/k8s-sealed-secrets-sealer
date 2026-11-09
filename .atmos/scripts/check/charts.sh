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

validate deploy/helm/control-plane
validate deploy/helm/agent
validate deploy/helm/agent --set capabilities.keys=true --set capabilities.renewal=true
