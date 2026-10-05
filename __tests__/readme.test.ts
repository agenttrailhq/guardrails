/**
 * The README's rule counts.
 *
 * The README states the corpus size and a per-pack count in the pack table, and
 * those numbers are the first thing a reader trusts. Nothing else ties them to the
 * code, so adding or removing a rule without touching the README would leave it
 * quietly wrong. This test makes that a red build instead.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PACKS, RULES, RULES_BY_PACK } from "../src/index.js";

const README = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8");

describe("the README's rule counts", () => {
  it("states the total the corpus actually has", () => {
    const stated = README.match(/\[(\d+) rules\]\(https:\/\/www\.agenttrail\.sh\/guardrails\)/);
    expect(stated?.[1]).toBe(String(RULES.length));
  });

  it("states the import section's total the corpus actually has", () => {
    const stated = README.match(/re-check (\d+)\s+rules/);
    expect(stated?.[1]).toBe(String(RULES.length));
  });

  it("lists every pack in the pack table, with its real rule count", () => {
    const rows = [...README.matchAll(/^\| \[`([a-z-]+)`\]\(src\/packs\/[a-z-]+\/\) \| (\d+) \|/gm)];
    const table = Object.fromEntries(rows.map(([, pack, count]) => [pack, Number(count)]));
    const actual = Object.fromEntries(PACKS.map((pack) => [pack, RULES_BY_PACK[pack].length]));
    expect(table).toEqual(actual);
  });
});
