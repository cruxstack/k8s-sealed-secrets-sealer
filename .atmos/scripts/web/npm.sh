#!/usr/bin/env bash
# Runs npm in web/ with the pinned Node, installing dependencies from the
# lockfile first when they are missing or older than the lockfile. Install
# scripts never run.
#   npm.sh install           install from the lockfile
#   npm.sh run <script> ...  run a package.json script
set -euo pipefail
source .atmos/scripts/web/node-env.sh
cd web

install() {
  echo "+ npm ci --ignore-scripts" >&2
  npm ci --ignore-scripts --no-audit --no-fund
}

if [[ "${1:-}" == "install" ]]; then
  install
  exit 0
fi

# npm records the installed tree in node_modules/.package-lock.json
if [[ ! -f node_modules/.package-lock.json || package-lock.json -nt node_modules/.package-lock.json ]]; then
  install
fi

echo "+ npm $*" >&2
exec npm "$@"
