#!/usr/bin/env bash
# cspell:words nullglob
# Waits for npm to serve a version just published from a tarball, then checks that npm serves
# that tarball's entry points.
#
# Usage: scripts/verify-published.sh <tarball>
#
# The name and version come from the tarball's package/package.json. A zero exit from npm
# publish does not mean the version is installable, so `npm view <name>@<version> version` is
# polled until it answers: $VERIFY_ATTEMPTS times (default 120), $VERIFY_INTERVAL seconds apart
# (default 30). Then main, module, types and exports as npm serves them must equal the
# tarball's; a version whose served entry points differ from the checked tarball fails.
#
# $NPM (default npm) is the command to query the registry with.
set -euo pipefail

fail() {
  echo "verify-published: $*" >&2
  exit 1
}

tarball="${1:-}"
[[ -f "$tarball" ]] || fail "no tarball at '${tarball}'"
npm_cmd="${NPM:-npm}"
attempts="${VERIFY_ATTEMPTS:-120}"
interval="${VERIFY_INTERVAL:-30}"

packed="$(tar -xzOf "$tarball" package/package.json)" || fail "${tarball} has no package/package.json"
field() {
  printf '%s' "$packed" | node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const v = JSON.parse(s)[process.argv[1]];
      process.stdout.write(typeof v === "string" ? v : "");
    });' "$1"
}
name="$(field name)"
version="$(field version)"
[[ -n "$name" && -n "$version" ]] || fail "${tarball} names no package or version"

for attempt in $(seq 1 "$attempts"); do
  got="$("$npm_cmd" view "${name}@${version}" version 2>/dev/null || true)"
  if [[ "$got" == "$version" ]]; then
    served="$("$npm_cmd" view "${name}@${version}" --json)" || fail "could not read ${name}@${version} from npm"
    PACKED="$packed" SERVED="$served" node -e '
      const packed = JSON.parse(process.env.PACKED);
      const served = JSON.parse(process.env.SERVED);
      // Key order is not significant; compare a canonical form.
      const canon = (v) =>
        v && typeof v === "object"
          ? Array.isArray(v)
            ? v.map(canon)
            : Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]))
          : v;
      const bad = ["main", "module", "types", "exports"].filter(
        (f) => JSON.stringify(canon(packed[f])) !== JSON.stringify(canon(served[f])),
      );
      for (const f of bad) {
        console.error(
          `verify-published: npm serves ${f} ${JSON.stringify(served[f])}, ` +
            `the tarball has ${JSON.stringify(packed[f])}`,
        );
      }
      process.exit(bad.length === 0 ? 0 : 1);' || exit 1
    echo "verify-published: ${name}@${version} is on npm with the tarball's entry points (attempt ${attempt})"
    exit 0
  fi
  if ((attempt < attempts)); then sleep "$interval"; fi
done
echo "::error::${name}@${version} did not appear on npm within $((attempts * interval)) seconds" >&2
exit 1
