#!/usr/bin/env bash
# Tests version.sh against throwaway Git repositories.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/version.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

# repo <commit subjects...>: a fresh repository with one commit per subject;
# "TAG vX.Y.Z" tags the commit before it
repo() {
  local dir
  dir="$(mktemp -d "${work}/repo.XXXX")"
  git -C "$dir" init -q
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name test
  git -C "$dir" config commit.gpgsign false
  git -C "$dir" config tag.gpgsign false
  for subject in "$@"; do
    if [[ "$subject" == TAG\ * ]]; then
      git -C "$dir" tag "${subject#TAG }"
    else
      git -C "$dir" commit -q --allow-empty -m "$subject"
    fi
  done
  echo "$dir"
}

# expect <name> <version> <commit subjects...>
expect() {
  local name="$1" want="$2" dir got
  shift 2
  dir="$(repo "$@")"
  got="$(cd "$dir" && GITHUB_OUTPUT='' bash "$script" "${dir}/notes.md")"
  if [[ "$got" == "version=${want}" ]]; then
    echo "ok - ${name}"
  else
    echo "FAIL - ${name}: got ${got}, want version=${want}"
    failures=$((failures + 1))
  fi
}

expect "first release" 0.1.0 "feat: a" "docs: b"
expect "nothing to release" "" "feat: a" "TAG v0.1.0" "docs: b" "ci: c" "test: d"
expect "fix" 0.1.1 "feat: a" "TAG v0.1.0" "fix(ui): b"
expect "dependency update" 0.1.1 "feat: a" "TAG v0.1.0" "chore(deps): bump x"
expect "chore is not released" "" "feat: a" "TAG v0.1.0" "chore: tidy"
expect "feature" 0.2.0 "feat: a" "TAG v0.1.0" "fix: b" "feat(agent): c"
expect "breaking before 1.0" 0.2.0 "feat: a" "TAG v0.1.0" "feat!: b"
expect "breaking after 1.0" 2.0.0 "feat: a" "TAG v1.4.2" "refactor(api)!: b"
expect "patch after 1.0" 1.4.3 "feat: a" "TAG v1.4.2" "perf: b"
expect "other tags are ignored" 0.1.1 "feat: a" "TAG v0.1.0" "TAG nightly" "fix: b"

# a BREAKING CHANGE footer, and the notes
dir="$(repo "feat: a" "TAG v1.0.0" "fix: b")"
git -C "$dir" commit -q --allow-empty -m "feat: c" -m "BREAKING CHANGE: the API moved"
got="$(cd "$dir" && GITHUB_OUTPUT='' bash "$script" "${dir}/notes.md")"
if [[ "$got" == "version=2.0.0" ]] && grep -q '^## Breaking changes' "${dir}/notes.md" &&
  grep -q '^- feat: c (' "${dir}/notes.md" && grep -q '^- fix: b (' "${dir}/notes.md" &&
  grep -q '^Changes since v1.0.0.' "${dir}/notes.md"; then
  echo "ok - breaking change footer and notes"
else
  echo "FAIL - breaking change footer and notes: ${got}"
  /bin/cat "${dir}/notes.md"
  failures=$((failures + 1))
fi

((failures == 0)) || exit 1
