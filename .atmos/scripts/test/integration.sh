#!/usr/bin/env bash
# Runs the tests that need real AWS service emulators (DynamoDB Local and
# local KMS in Docker) but no Kubernetes cluster.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

containers=()
cleanup() {
  for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
}
trap cleanup EXIT

wait_for() {
  for _ in $(seq 1 60); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.5
  done
  echo "Error: $1 did not come up" >&2
  return 1
}

# published_port <container> <port>: the random local port Docker chose
published_port() {
  docker port "$1" "${2}/tcp" | head -n 1 | sed 's/.*://'
}

dynamodb="$(docker run -d --rm -p 127.0.0.1::8000 "$DYNAMODB_LOCAL_IMAGE" \
  -jar DynamoDBLocal.jar -inMemory -sharedDb -port 8000)"
containers+=("$dynamodb")
kms="$(docker run -d --rm -p 127.0.0.1::8080 \
  -e KMS_REGION=us-east-1 -e KMS_ACCOUNT_ID=000000000000 -e KMS_SEED_PATH=/init/seed.yaml \
  -v "$(pwd)/dev/local-kms/seed.yaml:/init/seed.yaml:ro" "$LOCAL_KMS_IMAGE")"
containers+=("$kms")

export SEALER_TEST_DYNAMODB_ENDPOINT="http://127.0.0.1:$(published_port "$dynamodb" 8000)"
export SEALER_TEST_KMS_ENDPOINT="http://127.0.0.1:$(published_port "$kms" 8080)"
wait_for "$SEALER_TEST_DYNAMODB_ENDPOINT"
wait_for "$SEALER_TEST_KMS_ENDPOINT"

echo "+ go test -race -count=1 (DynamoDB Local ${SEALER_TEST_DYNAMODB_ENDPOINT}, local KMS ${SEALER_TEST_KMS_ENDPOINT})" >&2
go test -race -count=1 ./internal/store/... ./internal/envelope/... "$@"
