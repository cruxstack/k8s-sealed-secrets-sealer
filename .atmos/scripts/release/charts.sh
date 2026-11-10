#!/usr/bin/env bash
# Pushes the packaged charts in release/ to an OCI registry, and prints each
# chart's digest as "agent=<digest>" and "control-plane=<digest>" (in GitHub
# Actions, also to $GITHUB_OUTPUT as agent and control_plane).
#
#   REGISTRY_USER=... REGISTRY_TOKEN=... charts.sh oci://ghcr.io/cruxstack/charts
set -euo pipefail

target="${1:?usage: charts.sh oci://<registry>/<path>}"
[[ "$target" == oci://* ]] || {
  echo "Error: ${target} is not an oci:// reference" >&2
  exit 1
}
host="${target#oci://}"
host="${host%%/*}"
: "${REGISTRY_USER:?set REGISTRY_USER}" "${REGISTRY_TOKEN:?set REGISTRY_TOKEN}"

helm registry login "$host" --username "$REGISTRY_USER" --password-stdin <<<"$REGISTRY_TOKEN" >/dev/null
for chart in agent control-plane; do
  file="$(ls release/k8s-sealed-secrets-sealer-${chart}-[0-9]*.tgz)"
  echo "+ helm push ${file} ${target}" >&2
  pushed="$(helm push "$file" "$target" 2>&1)"
  echo "$pushed" >&2
  digest="$(sed -n 's/^Digest: //p' <<<"$pushed")"
  [[ "$digest" == sha256:* ]] || {
    echo "Error: no digest for ${file}" >&2
    exit 1
  }
  echo "${chart}=${digest}"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    echo "${chart//-/_}=${digest}" >>"$GITHUB_OUTPUT"
  fi
done
helm registry logout "$host" >/dev/null 2>&1 || true
