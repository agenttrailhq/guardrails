import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/**
 * Writes a gzipped npm-style tarball under `parent`: package/package.json from `manifest`, plus
 * README.md, LICENSE and each of `files` with placeholder contents. Returns its path.
 */
export function makeTarball(
  parent: string,
  manifest: Record<string, unknown>,
  files: string[],
): string {
  const root = mkdtempSync(join(parent, "tarball-"));
  const pkg = join(root, "package");
  for (const file of ["README.md", "LICENSE", ...files]) {
    mkdirSync(dirname(join(pkg, file)), { recursive: true });
    writeFileSync(join(pkg, file), "x\n");
  }
  writeFileSync(join(pkg, "package.json"), JSON.stringify(manifest, null, 2));
  const out = join(root, "pkg.tgz");
  // COPYFILE_DISABLE keeps macOS tar from adding AppleDouble entries.
  const r = spawnSync("tar", ["-czf", out, "-C", root, "package"], {
    encoding: "utf8",
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });
  if (r.status !== 0) throw new Error(`tar: ${r.stderr}`);
  return out;
}
