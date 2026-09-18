/**
 * Corpus uniqueness.
 *
 * Two rules with the same id make `rules disable <id>` ambiguous. Two rules with
 * the same predicate are a subtler waste: the guard evaluates both and reports
 * whichever it reaches first, so silencing the one you were shown does not stop
 * the alert.
 */

import { describe, expect, it } from "vitest";
import { PACKS, RULES, RULES_BY_PACK } from "../src/index.js";

describe("rule ids", () => {
  it("are unique across the whole corpus", () => {
    const seen = new Map<string, number>();
    for (const rule of RULES) seen.set(rule.id, (seen.get(rule.id) ?? 0) + 1);
    const duplicates = [...seen.entries()].filter(([, count]) => count > 1).map(([id]) => id);
    expect(duplicates).toEqual([]);
  });

  it("are unique per pack too, so a pack cannot repeat one internally", () => {
    for (const pack of PACKS) {
      const ids = RULES_BY_PACK[pack].map((rule) => rule.id);
      expect(new Set(ids).size, `pack ${pack} repeats a rule id`).toBe(ids.length);
    }
  });
});

describe("rule predicates", () => {
  it("are unique — two rules matching identically is one rule with two names", () => {
    const seen = new Map<string, string[]>();
    for (const rule of RULES) {
      const key = JSON.stringify(rule.match);
      seen.set(key, [...(seen.get(key) ?? []), rule.id]);
    }
    const collisions = [...seen.values()].filter((ids) => ids.length > 1);
    expect(collisions).toEqual([]);
  });
});

/**
 * Byte-equality misses the collisions this corpus actually creates.
 *
 * The harm the check above names — "the guard evaluates both and reports
 * whichever it reaches first, so silencing the one you were shown does not stop
 * the alert" — does not need the two predicates to be IDENTICAL. It needs them
 * to fire on the same commands, which near-misses do while looking nothing alike.
 *
 * Six pairs in this corpus sit that close: `require-approval-rm-rf` beside an
 * `rm -rf` rule, `block-force-push` beside a force-push rule,
 * `block-curl-pipe-to-shell` beside a pipe-to-shell rule, `warn-op-read-secret`
 * beside an `op read` rule, `block-env-file-read` beside a dotenv rule, and
 * `block-destructive-sql` beside a `drop table` rule. All six are resolved by NOT
 * writing the duplicate. This test is what stops the seventh.
 *
 * The measure is MUTUAL coverage. `dd.rm-rf-absolute` and
 * `require-approval-rm-rf` overlap heavily and deliberately — one blocks an
 * absolute-rooted wipe, the other holds the broader shape — but each catches
 * block fixtures the other does not, so they are two rules rather than one with
 * two names. Only a pair where EACH matches ALL of the other's positives has
 * collapsed into a duplicate.
 */
describe("no two rules are near-duplicates", () => {
  /**
   * A deliberately small stand-in for the evaluator, which is not part of this
   * package. It is used ONLY to compare two rules against each other, never to
   * prove a rule works.
   */
  function roughlyMatches(
    match: (typeof RULES)[number]["match"],
    fixture: { tool: string; command?: string; file_path?: string },
  ): boolean {
    const text = "command" in fixture ? fixture.command : undefined;
    const one = (
      condition: (typeof RULES)[number]["match"]["any_of"] extends readonly (infer C)[] | undefined
        ? C
        : never,
    ): boolean => {
      if (condition.label !== undefined) {
        const alternatives = condition.label.replace(/[{}]/g, "").split(",");
        const tool = fixture.tool.toLowerCase();
        // A `*`-suffixed alternative (e.g. `mcp__*`) is a prefix, like the engine's
        // label glob; everything else compares whole.
        const hit = (a: string): boolean => {
          const alt = a.toLowerCase();
          return alt.endsWith("*") ? tool.startsWith(alt.slice(0, -1)) : alt === tool;
        };
        if (!alternatives.some(hit)) return false;
      }
      if (condition.detail_contains !== undefined) {
        if (text === undefined || !condition.detail_contains.every((s) => text.includes(s))) {
          return false;
        }
      }
      if (condition.detail_matches !== undefined) {
        if (
          text === undefined ||
          !condition.detail_matches.some((p) => new RegExp(p, "i").test(text))
        ) {
          return false;
        }
      }
      if (condition.file_glob !== undefined) {
        // Path comparison needs picomatch, which this package does not depend on.
        // Treating a file condition as "not matched" makes the check CONSERVATIVE:
        // it can only ever under-report a collision, never invent one.
        return false;
      }
      return true;
    };
    const positives = [...(match.any_of ?? []), ...(match.all_of ?? [])];
    if (positives.length === 0 || !positives.some(one)) return false;
    return !(match.none_of ?? []).some(one);
  }

  it("no pair matches every one of the other's block fixtures", () => {
    const collisions: string[] = [];
    for (const a of RULES) {
      for (const b of RULES) {
        if (a.id >= b.id) continue;
        const aCoversB = b.fixtures.block.every((f) => roughlyMatches(a.match, f));
        const bCoversA = a.fixtures.block.every((f) => roughlyMatches(b.match, f));
        if (aCoversB && bCoversA) collisions.push(`${a.id} <-> ${b.id}`);
      }
    }
    expect(collisions).toEqual([]);
  });

  it("the check BITES — a rule compared with itself is a collision", () => {
    // Without this the loop above could be reporting nothing because
    // `roughlyMatches` returns false for everything, and 1,540 pairs would pass
    // having proven nothing at all.
    const rule = RULES.find((r) => r.id === "wt.reset-hard");
    expect(rule).toBeDefined();
    if (!rule) return;
    expect(rule.fixtures.block.every((f) => roughlyMatches(rule.match, f))).toBe(true);
  });

  it("does NOT flag the two rm -rf rules, which overlap on purpose", () => {
    // `dd.rm-rf-absolute` blocks an absolute-rooted wipe; `require-approval-rm-rf`
    // holds the broader shape. Each catches positives the other does not, which is
    // exactly what makes them two rules instead of one with two names.
    const absolute = RULES.find((r) => r.id === "dd.rm-rf-absolute");
    const approval = RULES.find((r) => r.id === "require-approval-rm-rf");
    expect(absolute && approval).toBeTruthy();
    if (!absolute || !approval) return;
    expect(approval.fixtures.block.every((f) => roughlyMatches(absolute.match, f))).toBe(false);
  });
});

describe("the corpus", () => {
  it("is no longer empty — the container shipped before the rules did", () => {
    expect(RULES.length).toBe(74);
  });

  it("exposes all eleven packs, each with rules in it", () => {
    expect(Object.keys(RULES_BY_PACK).sort()).toEqual([...PACKS].sort());
    for (const pack of PACKS) expect(RULES_BY_PACK[pack].length, pack).toBeGreaterThan(0);
  });
});
