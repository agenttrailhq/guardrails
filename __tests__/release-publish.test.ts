// cspell:words precheck NOSYSTEM esac
/**
 * scripts/release-publish.sh, run against a throwaway git repository with a stub `npm` and a
 * stub `pnpm`.
 *
 * The stub pnpm "packs" by copying $STUB_TARBALL into --pack-destination. The stub npm answers
 * the `npm view` calls of release-precheck.sh from environment variables and records each
 * `npm publish` in $STUB_LOG, so each case can assert what would have been uploaded, and under
 * which dist-tag.
 */

import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeTarball } from "./tarball-fixture.js";

const SCRIPT = fileURLToPath(new URL("../scripts/release-publish.sh", import.meta.url));
const NAME = "@agenttrail/guardrails";
const DIST = ["dist/index.js", "dist/index.cjs", "dist/index.d.ts"];

const GIT_ENV = {
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "Test",
  GIT_AUTHOR_EMAIL: "test@example.com",
  GIT_COMMITTER_NAME: "Test",
  GIT_COMMITTER_EMAIL: "test@example.com",
};

// STUB_VERSION: "published" | "missing"; STUB_LATEST: a version; STUB_PUBLISH_EXIT: exit code.
const NPM_STUB = `#!/usr/bin/env bash
case "$1" in
  view)
    case "$3" in
      version)
        if [ "$STUB_VERSION" = published ]; then echo "\${2##*@}"; exit 0; fi
        echo "npm error code E404" >&2; exit 1 ;;
      dist-tags.latest) echo "$STUB_LATEST" ;;
      *) echo "stub: unexpected field $3" >&2; exit 2 ;;
    esac ;;
  publish)
    echo "$*" >> "$STUB_LOG"
    exit "\${STUB_PUBLISH_EXIT:-0}" ;;
  *) echo "stub: unexpected $*" >&2; exit 2 ;;
esac
`;

const PNPM_STUB = `#!/usr/bin/env bash
if [ "$1" != pack ] || [ "$2" != --pack-destination ]; then echo "stub: unexpected $*" >&2; exit 2; fi
echo "pnpm $*" >> "$STUB_LOG"
cp "$STUB_TARBALL" "$3/agenttrail-guardrails.tgz"
`;

let dir: string;
let repo: string;
let npm: string;
let pnpm: string;

function git(...args: string[]): void {
  const r = spawnSync("git", ["-C", repo, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...GIT_ENV },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
}

function commitVersion(version: string): void {
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: NAME, version }, null, 2));
  git("add", "package.json");
  git("commit", "-q", "-m", `Release ${version}`);
  git("tag", `v${version}`);
}

function manifest(version: string, patch: Record<string, unknown> = {}) {
  return {
    name: NAME,
    version,
    main: "./dist/index.cjs",
    module: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: {
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js", require: "./dist/index.cjs" },
    },
    ...patch,
  };
}

function run(
  version: string,
  opts: {
    tarball: string;
    latest?: string;
    onNpm?: boolean;
    publishExit?: number;
    staleTarball?: boolean;
  },
) {
  const work = mkdtempSync(join(dir, "run-"));
  const log = join(work, "log");
  const packDir = join(work, "pack");
  writeFileSync(log, "");
  if (opts.staleTarball) {
    mkdirSync(packDir);
    writeFileSync(join(packDir, "old.tgz"), "");
  }
  const r = spawnSync("bash", [SCRIPT, version], {
    cwd: repo,
    encoding: "utf8",
    env: {
      ...process.env,
      ...GIT_ENV,
      NPM: npm,
      PNPM: pnpm,
      MAIN_REF: "HEAD",
      PACK_DIR: packDir,
      GITHUB_OUTPUT: "",
      STUB_LOG: log,
      STUB_TARBALL: opts.tarball,
      STUB_LATEST: opts.latest ?? "0.2.2",
      STUB_VERSION: opts.onNpm ? "published" : "missing",
      STUB_PUBLISH_EXIT: String(opts.publishExit ?? 0),
    },
  });
  const lines = readFileSync(log, "utf8").split("\n").filter(Boolean);
  return {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    packDir,
    packs: lines.filter((l) => l.startsWith("pnpm ")),
    publishes: lines.filter((l) => l.startsWith("publish ")),
  };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "release-publish-"));
  repo = join(dir, "repo");
  npm = join(dir, "npm");
  pnpm = join(dir, "pnpm");
  writeFileSync(npm, NPM_STUB);
  writeFileSync(pnpm, PNPM_STUB);
  chmodSync(npm, 0o755);
  chmodSync(pnpm, 0o755);
  spawnSync("git", ["init", "-q", "-b", "main", repo], { env: { ...process.env, ...GIT_ENV } });
  commitVersion("0.2.3");
  commitVersion("0.2.5");
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("release-publish.sh publishes", () => {
  it("the pnpm-packed tarball under latest, and prints the release as JSON", () => {
    const r = run("0.2.5", { tarball: makeTarball(dir, manifest("0.2.5"), DIST) });
    expect(r.status).toBe(0);
    expect(r.packs).toEqual([`pnpm pack --pack-destination ${r.packDir}`]);
    expect(r.publishes).toEqual([
      `publish ${r.packDir}/agenttrail-guardrails.tgz --provenance --access public --tag latest`,
    ]);
    expect(JSON.parse(r.stdout)).toEqual({
      name: "npm package (@latest dist-tag)",
      url: "https://www.npmjs.com/package/@agenttrail/guardrails/v/0.2.5",
      channel: "latest",
    });
  });

  it("a version below npm's latest under the backport dist-tag", () => {
    const r = run("0.2.3", { tarball: makeTarball(dir, manifest("0.2.3"), DIST), latest: "0.2.4" });
    expect(r.status).toBe(0);
    expect(r.publishes).toHaveLength(1);
    expect(r.publishes[0]).toMatch(/ --provenance --access public --tag backport$/);
    expect(JSON.parse(r.stdout).channel).toBe("backport");
  });
});

describe("release-publish.sh publishes nothing", () => {
  it("when the packed manifest points at src/", () => {
    const broken = manifest("0.2.5", {
      main: "./src/index.ts",
      exports: { ".": "./src/index.ts" },
    });
    const r = run("0.2.5", { tarball: makeTarball(dir, broken, DIST) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/manifest main points at '\.\/src\/index\.ts', under src\//);
    expect(r.stderr).toMatch(/failed the tarball check; nothing was published/);
    expect(r.publishes).toEqual([]);
    expect(r.stdout).toBe("");
  });

  it("when an exports target is not in the tarball", () => {
    const missing = manifest("0.2.5", {
      exports: {
        ".": { types: "./dist/index.d.ts", import: "./dist/nope.js", require: "./dist/index.cjs" },
      },
    });
    const r = run("0.2.5", { tarball: makeTarball(dir, missing, DIST) });
    expect(r.status).toBe(1);
    expect(r.packs).toHaveLength(1);
    expect(r.stderr).toMatch(
      /manifest exports\.\.\.import points at '\.\/dist\/nope\.js', which is not in the tarball/,
    );
    expect(r.stderr).toMatch(/failed the tarball check; nothing was published/);
    expect(r.publishes).toEqual([]);
    expect(r.stdout).toBe("");
  });

  it("when the packed version is not the release version", () => {
    const r = run("0.2.5", { tarball: makeTarball(dir, manifest("0.2.4"), DIST) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/packed version is '0\.2\.4', expected '0\.2\.5'/);
    expect(r.publishes).toEqual([]);
  });

  it("when npm already has the version, without packing", () => {
    const r = run("0.2.5", { tarball: makeTarball(dir, manifest("0.2.5"), DIST), onNpm: true });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/is already on npm/);
    expect(r.packs).toEqual([]);
    expect(r.publishes).toEqual([]);
  });

  it("when there is no tag for the version", () => {
    const r = run("0.2.6", { tarball: makeTarball(dir, manifest("0.2.6"), DIST) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/tag v0\.2\.6 does not exist/);
    expect(r.packs).toEqual([]);
  });

  it.each(["0.2", "v0.2.5", ""])("for the version argument %j", (version) => {
    const r = run(version, { tarball: makeTarball(dir, manifest("0.2.5"), DIST) });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/version must look like 1\.2\.3/);
    expect(r.packs).toEqual([]);
  });

  it("and prints no release when npm publish fails", () => {
    const r = run("0.2.5", {
      tarball: makeTarball(dir, manifest("0.2.5"), DIST),
      publishExit: 1,
    });
    expect(r.status).toBe(1);
    expect(r.publishes).toHaveLength(1);
    expect(r.stdout).toBe("");
  });
});

describe("release-publish.sh refuses a pack directory", () => {
  it("that already holds a tarball", () => {
    const r = run("0.2.5", {
      tarball: makeTarball(dir, manifest("0.2.5"), DIST),
      staleTarball: true,
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/already holds a tarball/);
    expect(r.packs).toEqual([]);
    expect(r.publishes).toEqual([]);
  });
});
