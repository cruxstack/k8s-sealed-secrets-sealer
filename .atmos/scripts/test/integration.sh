#!/usr/bin/env bash
# Runs the tests that need real AWS service emulators (DynamoDB Local in
# Docker) but no Kubernetes cluster.
set -euo pipefail
source .atmos/scripts/lib/dev.sh

container="$(docker run -d --rm -p 127.0.0.1::8000 "$DYNAMODB_LOCAL_IMAGE" \
  -jar DynamoDBLocal.jar -inMemory -sharedDb -port 8000)"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

port="$(docker port "$container" 8000/tcp | head -n 1 | sed 's/.*://')"
endpoint="http://127.0.0.1:${port}"
for _ in $(seq 1 60); do
  curl -s -o /dev/null "$endpoint" && break
  sleep 0.5
done

echo "+ go test -race -count=1 ./internal/store/... (DynamoDB Local at ${endpoint})" >&2
SEALER_TEST_DYNAMODB_ENDPOINT="$endpoint" go test -race -count=1 ./internal/store/... "$@"
