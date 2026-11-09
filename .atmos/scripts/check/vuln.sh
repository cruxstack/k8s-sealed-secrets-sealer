#!/usr/bin/env bash
# govulncheck at a pinned version. `go run` fetches it through the module
# proxy and verifies it against the Go checksum database.
set -euo pipefail
GOVULNCHECK_VERSION="v1.9.0"
echo "+ govulncheck@${GOVULNCHECK_VERSION} ./..." >&2
exec go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
