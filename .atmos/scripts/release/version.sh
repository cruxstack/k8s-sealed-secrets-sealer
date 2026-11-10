#!/usr/bin/env bash
# Computes the next release from the conventional commits since the last
# release tag (vX.Y.Z reachable from HEAD), and writes its notes.
#
#   version.sh [notes-file]
#
# Prints "version=X.Y.Z", empty when no commit since the last release needs
# one; in GitHub Actions it also writes that to $GITHUB_OUTPUT. The notes go
# to notes-file (default release/notes.md).
#
#   feat:                                 minor
#   fix:, perf:, refactor:, revert:,
#   build(deps):, chore(deps):            patch
#   type!: or a BREAKING CHANGE: footer   major (minor before 1.0.0)
#   anything else (docs:, ci:, test:...)  no release
set -euo pipefail

notes="${1:-release/notes.md}"

last="$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
range=HEAD
[[ -n "$last" ]] && range="${last}..HEAD"

# 0 none, 1 patch, 2 minor, 3 major
bump=0
raise() { ((bump < $1)) && bump=$1 || true; }
breaking=() features=() fixes=()
scope='(\([^)]*\))?'
while IFS=$'\x1f' read -r -d $'\x1e' sha subject body; do
  sha="${sha#$'\n'}"
  line="- ${subject} (${sha})"
  if [[ "$subject" =~ ^[a-z]+${scope}!: ]] || grep -qE '^BREAKING[ -]CHANGE:' <<<"$body"; then
    raise 3
    breaking+=("$line")
  elif [[ "$subject" =~ ^feat${scope}: ]]; then
    raise 2
    features+=("$line")
  elif [[ "$subject" =~ ^(fix|perf|refactor|revert)${scope}: || "$subject" =~ ^(build|chore)\(deps\): ]]; then
    raise 1
    fixes+=("$line")
  fi
done < <(git log --no-merges --format='%h%x1f%s%x1f%b%x1e' "$range")

version=""
if ((bump > 0)); then
  current="${last#v}"
  [[ -n "$current" ]] || current=0.0.0
  IFS=. read -r major minor patch <<<"$current"
  # before 1.0.0 a breaking change bumps the minor version
  ((major == 0 && bump == 3)) && bump=2
  case "$bump" in
    3) version="$((major + 1)).0.0" ;;
    2) version="${major}.$((minor + 1)).0" ;;
    1) version="${major}.${minor}.$((patch + 1))" ;;
  esac

  mkdir -p "$(dirname "$notes")"
  {
    section() {
      local title="$1"
      shift
      (($# > 0)) || return 0
      printf '## %s\n\n' "$title"
      printf '%s\n' "$@"
      printf '\n'
    }
    section "Breaking changes" "${breaking[@]+"${breaking[@]}"}"
    section "Features" "${features[@]+"${features[@]}"}"
    section "Fixes" "${fixes[@]+"${fixes[@]}"}"
    if [[ -n "$last" ]]; then
      printf 'Changes since %s.\n' "$last"
    else
      printf 'The first release.\n'
    fi
  } >"$notes"
fi

echo "version=${version}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=${version}" >>"$GITHUB_OUTPUT"
fi
