#!/usr/bin/env bash
# Source this to put the Node pinned in web/.node-version first on PATH,
# installing it into .tools/node/<version> on first use. The archive is
# verified against nodejs.org's SHASUMS256.txt.
#
# Node does not come from `atmos toolchain`: its registry entry for Node does
# not extract (the archive's bin/ is not found), so this does the same job.

NODE_VERSION="$(tr -d '[:space:]' < web/.node-version)"
NODE_HOME="${PWD}/.tools/node/${NODE_VERSION}"

install_node() {
  local os arch dir asset base work expected actual
  case "$(uname -s)" in
    Darwin) os=darwin ;;
    Linux) os=linux ;;
    *) echo "Error: unsupported OS $(uname -s)" >&2; return 1 ;;
  esac
  case "$(uname -m)" in
    arm64 | aarch64) arch=arm64 ;;
    x86_64 | amd64) arch=x64 ;;
    *) echo "Error: unsupported architecture $(uname -m)" >&2; return 1 ;;
  esac

  dir="node-v${NODE_VERSION}-${os}-${arch}"
  asset="${dir}.tar.gz"
  base="https://nodejs.org/dist/v${NODE_VERSION}"
  work="$(mktemp -d)"

  echo "+ downloading ${base}/${asset}" >&2
  curl -fsSL --retry 3 -o "${work}/${asset}" "${base}/${asset}"
  curl -fsSL --retry 3 -o "${work}/SHASUMS256.txt" "${base}/SHASUMS256.txt"
  expected="$(awk -v a="${asset}" '$2 == a { print $1 }' "${work}/SHASUMS256.txt")"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "${work}/${asset}" | awk '{ print $1 }')"
  else
    actual="$(shasum -a 256 "${work}/${asset}" | awk '{ print $1 }')"
  fi
  if [[ -z "${expected}" || "${actual}" != "${expected}" ]]; then
    echo "Error: checksum mismatch for ${asset} (expected ${expected:-none}, got ${actual})" >&2
    rm -rf "${work}"
    return 1
  fi

  # node and npm (npm is a script under lib/node_modules, linked from bin/)
  tar -xzf "${work}/${asset}" -C "${work}" "${dir}/bin" "${dir}/lib/node_modules/npm"
  rm -rf "${NODE_HOME}"
  mkdir -p "$(dirname "${NODE_HOME}")"
  mv "${work}/${dir}" "${NODE_HOME}"
  rm -rf "${work}"
  echo "+ installed node ${NODE_VERSION} into ${NODE_HOME}" >&2
}

if [[ "$("${NODE_HOME}/bin/node" --version 2>/dev/null)" != "v${NODE_VERSION}" ]]; then
  install_node
fi
export PATH="${NODE_HOME}/bin:${PATH}"
