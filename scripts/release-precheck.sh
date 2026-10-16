#!/usr/bin/env bash
# cspell:words precheck
# Checks that an existing release tag can be published to npm, and picks the npm dist-tag.
#
# Usage: scripts/release-precheck.sh <tag>
#
# Exits non-zero unless all of these hold:
#   - the tag looks like v1.2.3;
#   - the tag exists;
#   - the tag's commit is an ancestor of $MAIN_REF (default origin/main);
#   - package.json at the tag has the tag's version;
#   - npm does not already have that version.
#
# The dist-tag is "latest" when the version is higher than npm's current latest (or there is
# none), and $BACKPORT_TAG (default "backport") otherwise, so an older version never replaces
# a newer one as latest.
#
# Prints name=, version= and dist_tag= lines, and appends them to $GITHUB_OUTPUT when it is set.
# $NPM (default "npm") is the npm command to query the registry with.
set -euo pipefail

fail() {
  echo "release-precheck: $*" >&2
  exit 1
}

tag="${1:-}"
main_ref="${MAIN_REF:-origin/main}"
npm_cmd="${NPM:-npm}"
backport_tag="${BACKPORT_TAG:-backport}"

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must look like v1.2.3, got '${tag}'"
version="${tag#v}"

git rev-parse -q --verify "refs/tags/${tag}^{commit}" >/dev/null || fail "tag ${tag} does not exist"
git rev-parse -q --verify "${main_ref}^{commit}" >/dev/null || fail "${main_ref} does not exist"
commit="$(git rev-parse "refs/tags/${tag}^{commit}")"
git merge-base --is-ancestor "$commit" "$main_ref" || fail "tag ${tag} is not on ${main_ref}"

manifest="$(git show "${commit}:package.json")" || fail "no package.json at ${tag}"
field() {
  printf '%s' "$manifest" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const v = JSON.parse(s)[process.argv[1]];
      process.stdout.write(typeof v === "string" ? v : "");
    });' "$1"
}
name="$(field name)"
pkg_version="$(field version)"
[[ -n "$name" ]] || fail "package.json at ${tag} has no name"
[[ "$pkg_version" == "$version" ]] ||
  fail "package.json at ${tag} has version '${pkg_version}', expected '${version}'"

# Runs `npm view <spec> <field>`. Sets view_out to its stdout, and view_status to "found",
# "missing" (npm answered E404) or "error".
view() {
  local err rc
  err="$(mktemp)"
  set +e
  view_out="$("$npm_cmd" view "$1" "$2" 2>"$err")"
  rc=$?
  set -e
  view_out="$(printf '%s' "$view_out" | tr -d '[:space:]')"
  if [[ $rc -eq 0 && -n "$view_out" ]]; then
    view_status=found
  elif [[ $rc -eq 0 ]] || grep -q 'E404' "$err"; then
    view_status=missing
  else
    view_status=error
    sed 's/^/  npm: /' "$err" >&2
  fi
  rm -f "$err"
}

view "${name}@${version}" version
case "$view_status" in
  found) fail "${name}@${version} is already on npm" ;;
  error) fail "could not check npm for ${name}@${version}" ;;
esac

# True when $1 is a higher x.y.z than $2.
version_gt() {
  local a b i
  IFS=. read -r -a a <<<"$1"
  IFS=. read -r -a b <<<"$2"
  for i in 0 1 2; do
    ((10#${a[i]} > 10#${b[i]})) && return 0
    ((10#${a[i]} < 10#${b[i]})) && return 1
  done
  return 1
}

view "$name" dist-tags.latest
case "$view_status" in
  missing) dist_tag=latest ;;
  found)
    latest="${view_out%%-*}"
    [[ "$latest" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "npm latest is '${view_out}', not x.y.z"
    # A prerelease latest (1.2.3-rc.1) is below its release (1.2.3).
    if version_gt "$version" "$latest" || [[ "$version" == "$latest" && "$view_out" == *-* ]]; then
      dist_tag=latest
    else
      dist_tag="$backport_tag"
    fi
    ;;
  *) fail "could not read the latest dist-tag of ${name}" ;;
esac

out="name=${name}
version=${version}
dist_tag=${dist_tag}"
echo "$out"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "$out" >>"$GITHUB_OUTPUT"
fi
