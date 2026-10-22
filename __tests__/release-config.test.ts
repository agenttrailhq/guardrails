// cspell:words releaserc
/**
 * The release configuration publishes the pnpm-packed tarball, never the working directory.
 *
 * npm publish of the directory ignores publishConfig and ships the src/ entry points. The
 * release must instead go through scripts/release-publish.sh, which packs with pnpm, runs
 * scripts/check-tarball.py and publishes only that tarball.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

type Plugin = string | [string, Record<string, unknown>];

const CONFIG = JSON.parse(readFileSync(new URL("../.releaserc.json", import.meta.url), "utf8")) as {
  plugins: Plugin[];
};

function options(name: string): Record<string, unknown> {
  const entry = CONFIG.plugins.find((p) => (Array.isArray(p) ? p[0] : p) === name);
  if (entry === undefined) throw new Error(`${name} is not configured`);
  return Array.isArray(entry) ? entry[1] : {};
}

describe(".releaserc.json", () => {
  it("does not let @semantic-release/npm publish", () => {
    expect(options("@semantic-release/npm").npmPublish).toBe(false);
  });

  it("publishes through scripts/release-publish.sh with the release version", () => {
    expect(options("@semantic-release/exec").publishCmd).toMatch(
      /^MAIN_REF=HEAD bash scripts\/release-publish\.sh \$\{nextRelease\.version\}$/,
    );
  });

  it("publishes before @semantic-release/github creates the release", () => {
    const names = CONFIG.plugins.map((p) => (Array.isArray(p) ? p[0] : p));
    expect(names.indexOf("@semantic-release/exec")).toBeLessThan(
      names.indexOf("@semantic-release/github"),
    );
  });
});
