/**
 * The pack registry.
 *
 * The eight ids are shared with the rules that are authored against them and
 * with the guard's `config.json` `enabledPacks`, so this test pins the list
 * literally rather than deriving it from itself.
 *
 * A pack id also appears in a user's config file, so renaming one silently
 * disables the rules they had enabled. This test is what makes that rename show
 * up as a red build instead of a support ticket.
 */

import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { getRule, isPack, PACKS, RULES, RULES_BY_PACK, rulesForPack } from "../src/index.js";

const PACKS_DIR = fileURLToPath(new URL("../src/packs", import.meta.url));

describe("the eight pack ids", () => {
  it("are exactly these, in this order", () => {
    expect([...PACKS]).toEqual([
      "working-tree",
      "destructive-data",
      "prod-infra",
      "secret-exposure",
      "rce-supply-chain",
      "safety-bypass",
      "privilege-supply-chain",
      "file-scope",
    ]);
  });

  it("lead with working-tree — the most documented real-world agent failure", () => {
    expect(PACKS[0]).toBe("working-tree");
  });

  it("each have a directory on disk", () => {
    const onDisk = readdirSync(PACKS_DIR, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    expect(onDisk).toEqual([...PACKS].sort());
  });
});

describe("isPack", () => {
  it.each(PACKS)("accepts %s", (pack) => {
    expect(isPack(pack)).toBe(true);
  });

  it.each([["working_tree"], ["Working-Tree"], ["cost-loop"], [""]])("rejects %j", (candidate) => {
    expect(isPack(candidate)).toBe(false);
  });

  it("rejects the dropped cost/loop pack by name — it cannot block, so it is out", () => {
    expect(isPack("cost-loop")).toBe(false);
  });
});

describe("every rule's category is a real pack, and matches the pack it sits in", () => {
  it("holds for the whole corpus", () => {
    for (const pack of PACKS) {
      for (const rule of RULES_BY_PACK[pack]) {
        expect(isPack(rule.category), `${rule.id} has category ${rule.category}`).toBe(true);
        expect(rule.category, `${rule.id} is filed under ${pack}`).toBe(pack);
      }
    }
  });
});

describe("the catalog is assembled from PACKS, not by hand", () => {
  it("contains every pack's rules and nothing else", () => {
    const fromPacks = PACKS.flatMap((pack) => RULES_BY_PACK[pack]);
    expect(RULES).toEqual(fromPacks);
  });

  it("presents rules in declared pack order", () => {
    const categories = RULES.map((rule) => rule.category);
    const sorted = [...categories].sort(
      (a, b) =>
        PACKS.indexOf(a as (typeof PACKS)[number]) - PACKS.indexOf(b as (typeof PACKS)[number]),
    );
    expect(categories).toEqual(sorted);
  });
});

describe("lookup helpers", () => {
  it("rulesForPack returns that pack's list", () => {
    for (const pack of PACKS) expect(rulesForPack(pack)).toBe(RULES_BY_PACK[pack]);
  });

  it("getRule returns undefined for an unknown id rather than throwing", () => {
    expect(getRule("nope.not-a-rule")).toBeUndefined();
  });

  it("getRule finds every rule in the corpus by its id", () => {
    for (const rule of RULES) expect(getRule(rule.id)).toBe(rule);
  });
});
