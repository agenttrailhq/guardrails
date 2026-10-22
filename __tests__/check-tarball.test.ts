/**
 * scripts/check-tarball.py, run against tarballs built here.
 *
 * package.json keeps src/ entry points for development and lists the dist/ ones under
 * publishConfig. pnpm pack applies publishConfig; npm pack and npm publish do not, and ship the
 * src/ entry points, which are not in the tarball. The checker must fail that shape.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makeTarball } from "./tarball-fixture.js";

const SCRIPT = fileURLToPath(new URL("../scripts/check-tarball.py", import.meta.url));
const PKG = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const ENTRY_FIELDS = ["main", "module", "types", "exports"] as const;

type Manifest = Record<string, unknown>;

let dir: string;

/** Every string under an exports-style value. */
function targets(node: unknown): string[] {
  if (typeof node === "string") return [node];
  if (Array.isArray(node)) return node.flatMap(targets);
  if (node && typeof node === "object") return Object.values(node).flatMap(targets);
  return [];
}

/** The repository's package.json as pnpm packs it: publishConfig entry points applied. */
function pnpmPacked(): Manifest {
  const out: Manifest = { ...PKG };
  for (const field of ENTRY_FIELDS) {
    if (field in PKG.publishConfig) out[field] = PKG.publishConfig[field];
  }
  delete out.publishConfig;
  return out;
}

/** The repository's package.json as npm packs it: unchanged. */
function npmPacked(): Manifest {
  return { ...PKG };
}

function tarball(manifest: Manifest, files: string[]): string {
  return makeTarball(dir, manifest, files);
}

/** The dist/ files that the pnpm-packed manifest names. */
function distFiles(): string[] {
  const m = pnpmPacked();
  return [...new Set(ENTRY_FIELDS.flatMap((f) => targets(m[f])))].map((p) =>
    p.replace(/^\.\//, ""),
  );
}

function check(path: string, version = PKG.version as string) {
  const r = spawnSync("python3", [SCRIPT, path, "--package", PKG.name, "--version", version], {
    encoding: "utf8",
  });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "check-tarball-"));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("the repository's package.json", () => {
  it("has no src/ entry point once pnpm applies publishConfig", () => {
    const m = pnpmPacked();
    const all = ENTRY_FIELDS.flatMap((f) => targets(m[f]));
    expect(all.length).toBeGreaterThan(0);
    for (const t of all) expect(t).not.toMatch(/^(\.\/)?src(\/|$)/);
  });

  it("passes the check as pnpm packs it", () => {
    const r = check(tarball(pnpmPacked(), distFiles()));
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/none under src\//);
  });

  it("fails the check as npm packs it, on main and every exports entry", () => {
    const r = check(tarball(npmPacked(), distFiles()));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/manifest main points at '\.\/src\/index\.ts', under src\//);
    for (const key of Object.keys(PKG.exports)) {
      expect(r.stderr).toContain(`manifest exports.${key} points at '${PKG.exports[key]}'`);
    }
  });
});

describe("check-tarball.py fails an entry point under src/", () => {
  const dist = ["dist/index.js", "dist/index.cjs", "dist/index.d.ts"];
  const good = {
    name: PKG.name,
    version: PKG.version,
    main: "./dist/index.cjs",
    module: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: {
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js", require: "./dist/index.cjs" },
    },
  };

  it("accepts the dist/ shape", () => {
    expect(check(tarball(good, dist)).status).toBe(0);
  });

  it.each([
    ["main", { main: "./src/index.ts" }, "main"],
    ["module", { module: "./src/index.ts" }, "module"],
    ["types", { types: "src/index.ts" }, "types"],
    ["exports as a string", { exports: "./src/index.ts" }, "exports"],
    [
      "a nested exports condition",
      {
        exports: {
          ".": {
            import: { types: "./src/index.ts", default: "./dist/index.js" },
            require: "./dist/index.cjs",
          },
        },
      },
      "exports...import.types",
    ],
    [
      "an exports fallback array",
      { exports: { ".": ["./dist/index.js", "./src/index.ts"] } },
      "exports..[1]",
    ],
  ])("in %s", (_label, patch, field) => {
    const r = check(tarball({ ...good, ...patch }, dist));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(`manifest ${field} points at`);
    expect(r.stderr).toMatch(/under src\//);
  });

  it("even when the src/ file is in the tarball", () => {
    const r = check(tarball({ ...good, main: "./src/index.ts" }, [...dist, "src/index.ts"]));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/manifest main points at '\.\/src\/index\.ts', under src\//);
  });
});

describe("check-tarball.py fails an entry point that is not in the tarball", () => {
  const dist = [
    "dist/index.js",
    "dist/index.cjs",
    "dist/index.d.ts",
    "dist/guardrails.js",
    "dist/guardrails.cjs",
    "dist/guardrails.d.ts",
  ];
  const good = {
    name: PKG.name,
    version: PKG.version,
    main: "./dist/index.cjs",
    module: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: {
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js", require: "./dist/index.cjs" },
      "./guardrails": {
        types: "./dist/guardrails.d.ts",
        import: "./dist/guardrails.js",
        require: "./dist/guardrails.cjs",
      },
    },
  };

  it("accepts a tarball that has every target", () => {
    const r = check(tarball(good, dist));
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
  });

  it.each([
    ["main", { main: "./dist/nope.cjs" }, "main", "./dist/nope.cjs"],
    ["module", { module: "./dist/nope.js" }, "module", "./dist/nope.js"],
    ["types", { types: "./dist/nope.d.ts" }, "types", "./dist/nope.d.ts"],
    ["typings", { typings: "./dist/nope.d.ts" }, "typings", "./dist/nope.d.ts"],
    [
      "a subpath export's condition",
      {
        exports: {
          ...good.exports,
          "./guardrails": { ...good.exports["./guardrails"], import: "./dist/nope.js" },
        },
      },
      "exports../guardrails.import",
      "./dist/nope.js",
    ],
    [
      "a nested condition",
      {
        exports: {
          ...good.exports,
          ".": { import: { types: "./dist/nope.d.ts", default: "./dist/index.js" } },
        },
      },
      "exports...import.types",
      "./dist/nope.d.ts",
    ],
    [
      "an exports fallback array",
      { exports: { ...good.exports, ".": ["./dist/index.js", "./dist/nope.js"] } },
      "exports..[1]",
      "./dist/nope.js",
    ],
  ])("in %s", (_label, patch, field, target) => {
    const r = check(tarball({ ...good, ...patch }, dist));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain(
      `manifest ${field} points at '${target}', which is not in the tarball`,
    );
  });
});
