#!/usr/bin/env node
// @semantic-release/exec prepare for @agenttrail/guardrails: sync src/stamp.ts's
// CATALOG_VERSION (= the release version) and CATALOG_PUBLISHED_AT (= release time, UTC).
// @semantic-release/npm bumps package.json; stamp.test.ts pins CATALOG_VERSION to it.
import { readFileSync, writeFileSync } from "node:fs";
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version ?? "")) {
  console.error(`sr-stamp: bad version ${JSON.stringify(version)}`);
  process.exit(2);
}
const path = new URL("../src/stamp.ts", import.meta.url);
const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
let src = readFileSync(path, "utf8");
const before = src;
src = src.replace(/(export const CATALOG_VERSION = ")[^"]*(";)/, `$1${version}$2`);
src = src.replace(/(export const CATALOG_PUBLISHED_AT = ")[^"]*(";)/, `$1${now}$2`);
if (src === before) { console.error("sr-stamp: no substitution made"); process.exit(1); }
writeFileSync(path, src);
console.error(`sr-stamp: CATALOG_VERSION=${version} CATALOG_PUBLISHED_AT=${now}`);
