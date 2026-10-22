// cspell:words esac
/**
 * scripts/verify-published.sh, run with a stub `npm`.
 *
 * The stub answers `npm view <spec> version` once the call count reaches $STUB_APPEARS_AT, and
 * `npm view <spec> --json` with $STUB_SERVED, so each case can set what the registry serves.
 */

import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeTarball } from "./tarball-fixture.js";

const SCRIPT = fileURLToPath(new URL("../scripts/verify-published.sh", import.meta.url));
const NAME = "@agenttrail/guardrails";
const DIST = ["dist/index.js", "dist/index.cjs", "dist/index.d.ts"];

const NPM_STUB = `#!/usr/bin/env bash
count=$(( $(cat "$STUB_COUNT" 2>/dev/null || echo 0) + 1 ))
echo "$count" > "$STUB_COUNT"
if [ "$1" != view ]; then echo "stub: unexpected $*" >&2; exit 2; fi
case "$3" in
  version)
    if [ "$count" -ge "$STUB_APPEARS_AT" ]; then echo "\${2##*@}"; exit 0; fi
    echo "npm error code E404" >&2; exit 1 ;;
  --json) printf '%s\\n' "$STUB_SERVED" ;;
  *) echo "stub: unexpected field $3" >&2; exit 2 ;;
esac
`;

const PACKED = {
  name: NAME,
  version: "0.2.6",
  main: "./dist/index.cjs",
  module: "./dist/index.js",
  types: "./dist/index.d.ts",
  exports: {
    ".": { types: "./dist/index.d.ts", import: "./dist/index.js", require: "./dist/index.cjs" },
  },
};

let dir: string;
let npm: string;

function run(served: Record<string, unknown>, appearsAt = 1, attempts = 3) {
  const work = mkdtempSync(join(dir, "run-"));
  const r = spawnSync("bash", [SCRIPT, makeTarball(work, PACKED, DIST)], {
    encoding: "utf8",
    env: {
      ...process.env,
      NPM: npm,
      VERIFY_ATTEMPTS: String(attempts),
      VERIFY_INTERVAL: "0",
      STUB_COUNT: join(work, "count"),
      STUB_APPEARS_AT: String(appearsAt),
      STUB_SERVED: JSON.stringify(served),
    },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "verify-published-"));
  npm = join(dir, "npm");
  writeFileSync(npm, NPM_STUB);
  chmodSync(npm, 0o755);
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("verify-published.sh", () => {
  it("passes when npm serves the tarball's entry points, in any key order", () => {
    const served = {
      ...PACKED,
      exports: {
        ".": { require: "./dist/index.cjs", import: "./dist/index.js", types: "./dist/index.d.ts" },
      },
    };
    const r = run(served);
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(
      /@agenttrail\/guardrails@0\.2\.6 is on npm with the tarball's entry points/,
    );
  });

  it("waits for the version to appear", () => {
    const r = run(PACKED, 2);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/\(attempt 2\)/);
  });

  it("fails when npm serves src/ entry points", () => {
    const r = run({ ...PACKED, main: "./src/index.ts", exports: { ".": "./src/index.ts" } });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(
      'npm serves main "./src/index.ts", the tarball has "./dist/index.cjs"',
    );
    expect(r.stderr).toContain("npm serves exports");
  });

  it("fails when the version never appears", () => {
    const r = run(PACKED, 99, 2);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/@agenttrail\/guardrails@0\.2\.6 did not appear on npm/);
  });
});
