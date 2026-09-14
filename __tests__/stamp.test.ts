/**
 * The catalog stamp.
 *
 * `CATALOG_VERSION` is a hand-written copy of `package.json`'s `version`, and this
 * file is what makes the copy safe: bumping one without the other is a red build
 * rather than a tool that reports the wrong rule vintage to every user.
 *
 * That redness is also the release mechanism. Cutting a release edits
 * `package.json`, which fails here, which brings whoever cut it into `stamp.ts` —
 * where `CATALOG_PUBLISHED_AT` sits a few lines from the version they just changed.
 * Without this test the date would be advanced by memory, and eventually would not be.
 *
 * The date itself cannot be verified against an external truth from inside the repo,
 * so what is checked here is everything that CAN be: that it parses, that it is a
 * real instant, and that it is not in the future — which is what catches a typo'd
 * year, the failure mode that would otherwise reach the renderer's clock-skew branch
 * on every user's machine.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CATALOG_PUBLISHED_AT, CATALOG_VERSION } from "../src/index.js";
import * as rulesEntry from "../src/rules.js";

const PACKAGE_JSON = fileURLToPath(new URL("../package.json", import.meta.url));

function packageVersion(): string {
  const parsed: unknown = JSON.parse(readFileSync(PACKAGE_JSON, "utf8"));
  const version = (parsed as { version?: unknown }).version;
  if (typeof version !== "string") throw new Error("package.json has no string version");
  return version;
}

describe("both entry points carry the stamp", () => {
  it("the zod-free `/rules` subpath exposes it — the guard reads it from there", () => {
    // The guard imports `@agenttrail/guardrails/guardrails`, not the root, because the
    // root value-imports zod and the hook bundle must not carry a validator. A stamp
    // reachable only from the root would be reachable only at that cost.
    expect(rulesEntry.CATALOG_VERSION).toBe(CATALOG_VERSION);
    expect(rulesEntry.CATALOG_PUBLISHED_AT).toBe(CATALOG_PUBLISHED_AT);
  });
});

describe("CATALOG_VERSION", () => {
  it("is exactly package.json's version — the copy cannot drift unnoticed", () => {
    expect(CATALOG_VERSION).toBe(packageVersion());
  });

  it("is a semver triple, because the guard renders it as one", () => {
    expect(CATALOG_VERSION).toMatch(/^\d+\.\d+\.\d+(?:[-+].*)?$/);
  });
});

describe("CATALOG_PUBLISHED_AT", () => {
  it("is a parseable ISO-8601 instant", () => {
    expect(Number.isNaN(Date.parse(CATALOG_PUBLISHED_AT))).toBe(false);
  });

  it("round-trips through Date, so it is a real instant and not merely parseable", () => {
    // `Date.parse` accepts a lot. A round trip rejects the values it accepts loosely,
    // such as a month that overflows into the next one.
    expect(new Date(CATALOG_PUBLISHED_AT).toISOString()).toBe(
      new Date(Date.parse(CATALOG_PUBLISHED_AT)).toISOString(),
    );
  });

  it("carries an explicit UTC offset — a floating local time means a different age per timezone", () => {
    expect(CATALOG_PUBLISHED_AT).toMatch(/(?:Z|[+-]\d{2}:\d{2})$/);
  });

  it("is not in the future — the check that catches a typo'd year", () => {
    expect(Date.parse(CATALOG_PUBLISHED_AT)).toBeLessThanOrEqual(Date.now());
  });

  it("is not absurdly old — the other direction of the same typo", () => {
    // The package did not exist before 2026. A `2016` for `2026` lands here.
    expect(Date.parse(CATALOG_PUBLISHED_AT)).toBeGreaterThan(Date.parse("2026-01-01T00:00:00Z"));
  });
});
