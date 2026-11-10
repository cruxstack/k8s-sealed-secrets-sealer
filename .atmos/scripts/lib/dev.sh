#!/usr/bin/env bash
# Shared settings and helpers for the local k3d stack. Every setting can be
# overridden from the environment, which is how worktree and e2e stacks get a
# cluster and ports of their own.

SEALER_CLUSTER="${SEALER_CLUSTER:-sealer}"
KUBE_CONTEXT="k3d-${SEALER_CLUSTER}"
SEALER_REGISTRY="${SEALER_REGISTRY:-${SEALER_CLUSTER}-registry}"

export SEALER_TILT_PORT="${SEALER_TILT_PORT:-10350}"
export SEALER_CONTROL_PLANE_PORT="${SEALER_CONTROL_PLANE_PORT:-4100}"
export SEALER_DYNAMODB_PORT="${SEALER_DYNAMODB_PORT:-4102}"
export SEALER_KMS_PORT="${SEALER_KMS_PORT:-4103}"
export SEALER_GITHUB_PORT="${SEALER_GITHUB_PORT:-4104}"

# The upstream sealed-secrets chart, verified against the checksum of the
# release asset before use.
SEALED_SECRETS_CHART_REPO="https://bitnami.github.io/sealed-secrets"
SEALED_SECRETS_CHART_VERSION="2.22.0"
SEALED_SECRETS_CHART_SHA256="1ed23bb224652aa6c8477979d4bddccd207205b27b12b120f62f360890c80606"
export SEALED_SECRETS_CHART_DIR=".tools/charts/sealed-secrets-${SEALED_SECRETS_CHART_VERSION}"

BUILD_DIR=".tools/build"

# The local control plane's admin token, from its local-only Secret.
LOCAL_ADMIN_TOKEN="$(sed -n 's/^  APP_ADMIN_TOKEN: *//p' dev/k3d/control-plane-secret.yaml)"

# DynamoDB Local, for the integration tests that run without a cluster.
DYNAMODB_LOCAL_IMAGE="amazon/dynamodb-local:3.3.2@sha256:6ada631ec7aa5fc83446855eb17233e3dad184fec47477e8140c6c569cfe0c86"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

cluster_exists() {
  k3d cluster list --no-headers 2>/dev/null | awk '{print $1}' | grep -qx "$SEALER_CLUSTER"
}

registry_name() {
  k3d registry list --no-headers 2>/dev/null \
    | awk -v plain="$SEALER_REGISTRY" -v prefixed="k3d-${SEALER_REGISTRY}" '$1 == plain || $1 == prefixed { print $1; exit }'
}

ensure_cluster() {
  local registry
  if cluster_exists; then
    k3d cluster start "$SEALER_CLUSTER" >/dev/null
    return
  fi
  registry="$(registry_name)"
  local registry_flags=(--registry-create "$SEALER_REGISTRY")
  [[ -n "$registry" ]] && registry_flags=(--registry-use "$registry")
  echo "+ k3d cluster create ${SEALER_CLUSTER}" >&2
  # traefik and metrics-server are not used; leaving them out saves memory
  k3d cluster create "$SEALER_CLUSTER" --no-lb --wait "${registry_flags[@]}" \
    --k3s-arg '--disable=traefik@server:*' \
    --k3s-arg '--disable=metrics-server@server:*' >&2
}

delete_cluster() {
  local registry
  if cluster_exists; then
    k3d cluster delete "$SEALER_CLUSTER" >&2
  fi
  registry="$(registry_name)"
  if [[ -n "$registry" ]]; then
    k3d registry delete "$registry" >&2
  fi
}

pull_charts() {
  local tgz="${SEALED_SECRETS_CHART_DIR}.tgz" tmp actual
  [[ -f "${SEALED_SECRETS_CHART_DIR}/Chart.yaml" ]] && return
  mkdir -p "$(dirname "$SEALED_SECRETS_CHART_DIR")"
  if [[ ! -f "$tgz" ]]; then
    tmp="$(mktemp -d)"
    echo "+ helm pull sealed-secrets ${SEALED_SECRETS_CHART_VERSION}" >&2
    helm pull sealed-secrets --repo "$SEALED_SECRETS_CHART_REPO" \
      --version "$SEALED_SECRETS_CHART_VERSION" --destination "$tmp" >&2
    mv "${tmp}/sealed-secrets-${SEALED_SECRETS_CHART_VERSION}.tgz" "$tgz"
    rm -rf "$tmp"
  fi
  actual="$(sha256_of "$tgz")"
  if [[ "$actual" != "$SEALED_SECRETS_CHART_SHA256" ]]; then
    rm -f "$tgz"
    echo "Error: sealed-secrets chart checksum mismatch (got ${actual})" >&2
    return 1
  fi
  tmp="$(mktemp -d)"
  tar -xzf "$tgz" -C "$tmp"
  rm -rf "$SEALED_SECRETS_CHART_DIR"
  mv "${tmp}/sealed-secrets" "$SEALED_SECRETS_CHART_DIR"
  rm -rf "$tmp"
}

# Builds the web UI into internal/webui/dist/app, where the control plane
# binary embeds it, with the pinned Node (installing it and the lockfile's
# dependencies on first use, install scripts disabled).
build_web() {
  bash .atmos/scripts/web/npm.sh run build >&2
}

# Builds Linux binaries for the k3d nodes, which share the Docker host's
# architecture. Tilt wraps them in images (dev/docker/Dockerfile).
build_binaries() {
  local goarch="${SEALER_GOARCH:-$(go env GOARCH)}" bin
  mkdir -p "$BUILD_DIR"
  for bin in server agent mock-github; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
      go build -trimpath -o "${BUILD_DIR}/${bin}" "./cmd/${bin}"
  done
}

# Prints the simulated cluster names from dev/stack.yaml, one per line.
stack_clusters() {
  sed -n 's/^  - name: *//p' dev/stack.yaml
}

# Prints a deployment's log events of one kind as JSON lines.
log_events() {
  local namespace="$1" deployment="$2" event="$3"
  kubectl --context "$KUBE_CONTEXT" -n "$namespace" logs "deploy/${deployment}" 2>/dev/null \
    | grep -F "\"event\":\"${event}\"" || true
}
