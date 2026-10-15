/**
 * The README's guardrail counts.
 *
 * The README states the corpus size and a per-pack count in the pack table, and
 * those numbers are the first thing a reader trusts. Nothing else ties them to the
 * code, so adding or removing a guardrail without touching the README would leave it
 * quietly wrong. This test makes that a red build instead.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { getRule, OWASP_IDS, PACKS, type Pack, RULES, RULES_BY_PACK } from "../src/index.js";

const README = readFileSync(fileURLToPath(new URL("../README.md", import.meta.url)), "utf8");

describe("the README's guardrail counts", () => {
  it("states the total the corpus actually has", () => {
    const stated = README.match(
      /\[(\d+) guardrails\]\(https:\/\/www\.agenttrail\.sh\/guardrails\)/,
    );
    expect(stated?.[1]).toBe(String(RULES.length));
  });

  it("states the import section's total the corpus actually has", () => {
    const stated = README.match(/re-check (\d+)\s+guardrails/);
    expect(stated?.[1]).toBe(String(RULES.length));
  });

  it("lists every pack in the pack table, with its real guardrail count", () => {
    const rows = [...README.matchAll(/^\| \[`([a-z-]+)`\]\(src\/packs\/[a-z-]+\/\) \| (\d+) \|/gm)];
    const table = Object.fromEntries(rows.map(([, pack, count]) => [pack, Number(count)]));
    const actual = Object.fromEntries(PACKS.map((pack) => [pack, RULES_BY_PACK[pack].length]));
    expect(table).toEqual(actual);
  });
});

/** The README's "OWASP coverage" section, up to the next heading. */
function owaspSection(): string {
  const start = README.indexOf("## OWASP coverage");
  const end = README.indexOf("\n## ", start + 1);
  return README.slice(start, end);
}

/** Every OWASP id written in a piece of text. */
function idsIn(text: string): string[] {
  return [...text.matchAll(/\b(?:ASI|LLM)\d{2}\b/g)].map(([id]) => id);
}

/** The OWASP table: each row's packs, its id cells (agentic and LLM), in README order. */
function owaspRows(): { packs: Pack[]; cells: string }[] {
  return owaspSection()
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .map((line) => {
      const [packCell = "", agentic = "", llm = ""] = line.split("|").slice(1);
      const packs = [...packCell.matchAll(/`([a-z-]+)`/g)].map(([, p]) => p as Pack);
      return { packs, cells: `${agentic}|${llm}` };
    });
}

describe("the README's OWASP table", () => {
  it("lists every pack exactly once", () => {
    const listed = owaspRows().flatMap((row) => row.packs);
    expect([...listed].sort()).toEqual([...PACKS].sort());
  });

  it("gives each row exactly the ids its packs' guardrails carry", () => {
    for (const row of owaspRows()) {
      const tagged = new Set(
        row.packs.flatMap((pack) => RULES_BY_PACK[pack].flatMap((r) => r.owasp ?? [])),
      );
      expect(new Set(idsIn(row.cells)), row.packs.join(", ")).toEqual(tagged);
    }
  });

  it("names a guardrail beside an id only when that guardrail carries the id", () => {
    const named = [...owaspSection().matchAll(/\b((?:ASI|LLM)\d{2})\b[^,|(]*\(`([^`]+)`\)/g)];
    expect(named.length).toBeGreaterThan(0);
    for (const [, id, ruleId] of named) {
      expect(getRule(ruleId as string)?.owasp, `${ruleId} ${id}`).toContain(id);
    }
  });

  it("splits the twenty ids into ones a guardrail cites and ones the README says no guardrail can address", () => {
    const cited = new Set(RULES.flatMap((rule) => rule.owasp ?? []));
    const listStart = owaspSection().indexOf("What the guardrails cannot address");
    const notAddressed = new Set(idsIn(owaspSection().slice(listStart)));
    for (const id of notAddressed)
      expect(cited.has(id as (typeof OWASP_IDS)[number]), id).toBe(false);
    expect([...cited, ...notAddressed].sort()).toEqual([...OWASP_IDS].sort());
  });
});
