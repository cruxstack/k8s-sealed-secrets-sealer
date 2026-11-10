#!/usr/bin/env bash
# Builds a release's files into release/:
#
#   k8s-sealed-secrets-sealer-lambda_amd64.zip  the control plane for Lambda
#   k8s-sealed-secrets-sealer-lambda_arm64.zip  (provided.al2023, "bootstrap")
#   k8s-sealed-secrets-sealer-agent-X.Y.Z.tgz          the Helm charts
#   k8s-sealed-secrets-sealer-control-plane-X.Y.Z.tgz
#   checksums.txt                               SHA-256 of each
#
# The container images are built from the Dockerfile. The Lambda zips are
# reproducible: the same commit and version give the same bytes.
#
#   artifacts.sh X.Y.Z
set -euo pipefail

version="${1:?usage: artifacts.sh X.Y.Z}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "Error: ${version} is not a semantic version (X.Y.Z)" >&2
  exit 1
}
out=release
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
mkdir -p "$out"
rm -f "$out"/*.zip "$out"/*.tgz "$out"/checksums.txt

# the control plane embeds the web UI
bash .atmos/scripts/web/npm.sh run build >&2

ldflags="-s -w -buildid= -X github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version.Version=v${version}"
for arch in amd64 arm64; do
  echo "+ go build ./cmd/lambda (linux/${arch}, v${version})" >&2
  mkdir -p "${build}/${arch}"
  # lambda.norpc leaves out the RPC mode only the go1.x runtime used
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -tags lambda.norpc -ldflags "$ldflags" \
    -o "${build}/${arch}/bootstrap" ./cmd/lambda
  # a fixed time and mode, so the zip depends only on the binary
  chmod 0755 "${build}/${arch}/bootstrap"
  TZ=UTC touch -t 198001010000 "${build}/${arch}/bootstrap"
  (cd "${build}/${arch}" && zip -X -q "${OLDPWD}/${out}/k8s-sealed-secrets-sealer-lambda_${arch}.zip" bootstrap)
done

for chart in agent control-plane; do
  echo "+ helm package deploy/helm/${chart} (${version})" >&2
  helm package "deploy/helm/${chart}" --version "$version" --app-version "$version" -d "$out" >/dev/null
done

(
  cd "$out"
  if command -v sha256sum >/dev/null; then
    sha256sum ./*.zip ./*.tgz
  else
    shasum -a 256 ./*.zip ./*.tgz
  fi | sed 's| \./| |' >checksums.txt
)
echo "Release ${version} files in ${out}/:" >&2
ls -l "$out" >&2
