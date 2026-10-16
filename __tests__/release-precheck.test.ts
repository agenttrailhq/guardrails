// cspell:words precheck esac NOSYSTEM
/**
 * scripts/release-precheck.sh, run against a throwaway git repository and a stub `npm`.
 *
 * The stub answers `npm view <pkg>@<version> version` and `npm view <pkg> dist-tags.latest`
 * from environment variables, so each case controls what the registry reports.
 */

import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const SCRIPT = fileURLToPath(new URL("../scripts/release-precheck.sh", import.meta.url));
const NAME = "@agenttrail/guardrails";

// An isolated git: no user or system config, no hooks, no signing.
const GIT_ENV = {
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.com",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.com",
};

// Stub npm. STUB_VERSION: "published" | "missing" | "error"; STUB_LATEST: a version or "none".
const NPM_STUB = `#!/usr/bin/env bash
if [ "$1" != "view" ]; then echo "stub: unexpected $*" >&2; exit 2; fi
case "$3" in
  version)
    case "$STUB_VERSION" in
      published) echo "\${2##*@}" ;;
      missing) echo "npm error code E404" >&2; exit 1 ;;
      *) echo "npm error code ETIMEDOUT" >&2; exit 1 ;;
    esac ;;
  dist-tags.latest)
    if [ "$STUB_LATEST" = none ]; then echo "npm error code E404" >&2; exit 1; fi
    echo "$STUB_LATEST" ;;
  *) echo "stub: unexpected field $3" >&2; exit 2 ;;
esac
`;

let dir: string;
let repo: string;
let npm: string;

function git(...args: string[]): string {
  const r = spawnSync("git", ["-C", repo, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...GIT_ENV },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout.trim();
}

function commitVersion(version: string, message: string): void {
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: NAME, version }, null, 2));
  git("add", "package.json");
  git("commit", "-q", "-m", message);
}

function run(tag: string, stub: { version?: string; latest?: string } = {}) {
  const r = spawnSync("bash", [SCRIPT, tag], {
    cwd: repo,
    encoding: "utf8",
    env: {
      ...process.env,
      ...GIT_ENV,
      NPM: npm,
      GITHUB_OUTPUT: "",
      STUB_VERSION: stub.version ?? "missing",
      STUB_LATEST: stub.latest ?? "0.2.2",
    },
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "release-precheck-"));
  repo = join(dir, "repo");
  npm = join(dir, "npm");
  writeFileSync(npm, NPM_STUB);
  chmodSync(npm, 0o755);

  spawnSync("git", ["init", "-q", "-b", "main", repo], { env: { ...process.env, ...GIT_ENV } });
  commitVersion("0.2.3", "Release 0.2.3");
  git("tag", "v0.2.3");
  commitVersion("0.2.4", "Release 0.2.4");
  git("tag", "v0.2.4");
  git("tag", "v0.2.5"); // points at a commit whose package.json says 0.2.4
  git("update-ref", "refs/remotes/origin/main", "HEAD");

  // A tagged commit that is not on main.
  git("checkout", "-q", "-b", "side");
  commitVersion("0.9.0", "side change");
  git("tag", "v0.9.0");
  git("checkout", "-q", "main");
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("release-precheck.sh refuses", () => {
  it.each(["0.2.4", "v0.2", "v0.2.4-rc.1", "v0.2.4 ", "", "latest"])("the tag format %j", (tag) => {
    const r = run(tag);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/tag must look like v1\.2\.3/);
  });

  it("a tag that does not exist", () => {
    const r = run("v0.3.0");
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/tag v0\.3\.0 does not exist/);
  });

  it("a tag whose commit is not on origin/main", () => {
    const r = run("v0.9.0");
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/tag v0\.9\.0 is not on origin\/main/);
  });

  it("a tag whose package.json has another version", () => {
    const r = run("v0.2.5");
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/has version '0\.2\.4', expected '0\.2\.5'/);
  });

  it("a version that is already on npm", () => {
    const r = run("v0.2.4", { version: "published" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/@agenttrail\/guardrails@0\.2\.4 is already on npm/);
  });

  it("when npm cannot be asked", () => {
    const r = run("v0.2.4", { version: "error" });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/could not check npm/);
  });
});

describe("release-precheck.sh accepts", () => {
  it("an unpublished tag on main, as latest when it is higher than npm's latest", () => {
    const r = run("v0.2.4", { latest: "0.2.2" });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.stdout).toBe("name=@agenttrail/guardrails\nversion=0.2.4\ndist_tag=latest\n");
  });

  it("an older unpublished tag under a non-latest dist-tag", () => {
    const r = run("v0.2.3", { latest: "0.2.4" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("dist_tag=backport\n");
  });

  it("the version equal to a prerelease latest, as latest", () => {
    const r = run("v0.2.4", { latest: "0.2.4-rc.1" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("dist_tag=latest\n");
  });

  it("a package with no latest dist-tag yet, as latest", () => {
    const r = run("v0.2.4", { latest: "none" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("dist_tag=latest\n");
  });
});
