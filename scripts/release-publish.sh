#!/usr/bin/env bash
# cspell:words precheck nullglob
# Packs the package with pnpm, checks the tarball, and publishes that tarball to npm.
#
# Usage: scripts/release-publish.sh <version>
#
# Run from the package root, with the release tag v<version> already created.
#
#   1. scripts/release-precheck.sh v<version>: the tag exists and is on $MAIN_REF (default
#      origin/main), package.json at the tag has <version>, and npm does not have it yet. It also
#      picks the dist-tag: latest only when <version> is higher than npm's current latest.
#   2. pnpm pack into $PACK_DIR (default: a new temporary directory), which must not already hold
#      a tarball. pnpm applies the publishConfig entry points (dist/), which npm does not.
#   3. scripts/check-tarball.py on the tarball, with the package name and <version>.
#   4. npm publish <tarball> --provenance --access public --tag <dist-tag>. npm uploads the packed
#      tarball unchanged.
#
# Progress goes to stderr. On success, stdout is one JSON object naming the release, the form
# @semantic-release/exec reads from a publishCmd. $NPM (default npm) and $PNPM (default pnpm)
# are the commands to run.
set -euo pipefail

fail() {
  echo "release-publish: $*" >&2
  exit 1
}

version="${1:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version must look like 1.2.3, got '${version}'"
tag="v${version}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
npm_cmd="${NPM:-npm}"
pnpm_cmd="${PNPM:-pnpm}"

# 1. Refusals and the dist-tag. The precheck's own lines are kept off stdout.
precheck="$(GITHUB_OUTPUT='' bash "$here/release-precheck.sh" "$tag")" || exit 1
name="$(printf '%s\n' "$precheck" | sed -n 's/^name=//p')"
dist_tag="$(printf '%s\n' "$precheck" | sed -n 's/^dist_tag=//p')"
[[ -n "$name" && -n "$dist_tag" ]] || fail "release-precheck.sh gave no name or dist_tag"
echo "release-publish: ${name}@${version}, dist-tag ${dist_tag}" >&2

# 2. Pack.
pack_dir="${PACK_DIR:-$(mktemp -d)}"
mkdir -p "$pack_dir"
shopt -s nullglob
existing=("$pack_dir"/*.tgz)
((${#existing[@]} == 0)) || fail "${pack_dir} already holds a tarball"
"$pnpm_cmd" pack --pack-destination "$pack_dir" >&2
tarballs=("$pack_dir"/*.tgz)
shopt -u nullglob
((${#tarballs[@]} == 1)) || fail "expected one tarball in ${pack_dir}, found ${#tarballs[@]}"
tarball="${tarballs[0]}"

# 3. Check what will be uploaded: name, version, contents and entry points.
python3 "$here/check-tarball.py" "$tarball" --package "$name" --version "$version" >&2 ||
  fail "${tarball} failed the tarball check; nothing was published"

# 4. Publish.
"$npm_cmd" publish "$tarball" --provenance --access public --tag "$dist_tag" >&2

NAME="$name" VERSION="$version" DIST_TAG="$dist_tag" node -e '
  const { NAME, VERSION, DIST_TAG } = process.env;
  process.stdout.write(JSON.stringify({
    name: "npm package (@" + DIST_TAG + " dist-tag)",
    url: "https://www.npmjs.com/package/" + NAME + "/v/" + VERSION,
    channel: DIST_TAG,
  }) + "\n");'
