/**
 * The ReDoS guard, tested directly.
 *
 * `hasNestedUnboundedQuantifier` is the one piece of real logic in this package
 * — everything else is a schema declaration — and it is the piece with the
 * highest cost of being subtly wrong in either direction:
 *
 *   - Too permissive, and a rule ships that can backtrack. The guard has a 10s
 *     Claude Code timeout, no internal watchdog, and it **fails open**, so a
 *     backtracking pattern does not run slowly — it lets the action through.
 *     A rule that appears enforced and is not is the worst failure this product
 *     has.
 *   - Too strict, and it rejects ordinary rules. `(?:rm|rmdir)\s+-rf` and
 *     `([a-z]+)` are the shapes real rules are written in.
 *
 * These tests pin the BEHAVIOR itself, over concrete patterns in both directions.
 */

import { describe, expect, it } from "vitest";
import { hasNestedUnboundedQuantifier } from "../src/index.js";

describe("rejects nested unbounded quantifiers (star height >= 2)", () => {
  it.each([
    ["(a+)+", "the textbook case"],
    ["(a*)*", "star inside star"],
    ["(a+)*", "plus inside star"],
    ["(a*)+", "star inside plus"],
    ["(\\s+x?)+", "the shape in the shipped docstring"],
    ["([a-z]+)+", "a character class inside a quantified group"],
    ["(a{2,})+", "an explicitly unbounded {n,} inside a quantified group"],
    ["((a+))+", "nested groups"],
    ["(a+){2,}", "an unbounded {n,} applied to the outer group"],
  ])("%s — %s", (pattern) => {
    expect(hasNestedUnboundedQuantifier(pattern)).toBe(true);
  });
});

describe("accepts patterns real rules are written in", () => {
  it.each([
    ["a+", "a bare quantifier"],
    ["a*", "a bare star"],
    ["(ab)+", "a quantified group with no inner quantifier"],
    ["(a|b)*", "alternation under a star"],
    ["\\bgit\\s+reset\\s+--hard\\b", "the documented example rule"],
    ["(?:rm|rmdir)\\s+-rf", "a non-capturing alternation"],
    ["(a{2,3})+", "a BOUNDED {n,m} inside a quantified group"],
    ["(a+){3}", "a bounded {n} applied to the outer group"],
    ["[a-z]+", "a quantified character class, ungrouped"],
    ["", "the empty pattern"],
    ["x", "a literal"],
  ])("%s — %s", (pattern) => {
    expect(hasNestedUnboundedQuantifier(pattern)).toBe(false);
  });
});

/**
 * The cases that separate a real scanner from a regex over the pattern text. A
 * naive implementation gets every one of these wrong, and each wrong answer is
 * either a rejected valid rule or an accepted dangerous one.
 */
describe("distinguishes syntax from literal characters", () => {
  it("does not treat a quantifier INSIDE a character class as a quantifier", () => {
    // `[*+]` matches the literal characters `*` and `+`. Reading them as
    // quantifiers would reject a perfectly ordinary rule.
    expect(hasNestedUnboundedQuantifier("([*+])+")).toBe(false);
  });

  it("does not treat an ESCAPED quantifier as a quantifier", () => {
    expect(hasNestedUnboundedQuantifier("(\\+)+")).toBe(false);
    expect(hasNestedUnboundedQuantifier("(\\*)+")).toBe(false);
  });

  it("does not treat an ESCAPED parenthesis as a group", () => {
    // `\(a+\)+` has no group at all — the parens are literal.
    expect(hasNestedUnboundedQuantifier("\\(a+\\)+")).toBe(false);
  });

  it("does not treat a bracket inside a character class as opening another", () => {
    expect(hasNestedUnboundedQuantifier("([\\][a-z]+)+")).toBe(true);
  });

  it("ignores an escape inside a character class", () => {
    expect(hasNestedUnboundedQuantifier("([\\]]+)+")).toBe(true);
    expect(hasNestedUnboundedQuantifier("[\\]]+")).toBe(false);
  });

  it("does not treat a parenthesis inside a character class as a group", () => {
    expect(hasNestedUnboundedQuantifier("[()]+")).toBe(false);
  });

  it("survives unbalanced parentheses rather than throwing", () => {
    // The RegExp compile in the schema catches these; this function must not be
    // the thing that explodes first, or the error message names the wrong cause.
    expect(() => hasNestedUnboundedQuantifier(")a+)+")).not.toThrow();
    expect(() => hasNestedUnboundedQuantifier("((a+")).not.toThrow();
  });

  it("treats an unterminated character class as still open, and does not throw", () => {
    expect(() => hasNestedUnboundedQuantifier("([a-z+)+")).not.toThrow();
  });

  it("handles a trailing escape without reading past the end", () => {
    expect(() => hasNestedUnboundedQuantifier("(a+)+\\")).not.toThrow();
    expect(() => hasNestedUnboundedQuantifier("\\")).not.toThrow();
  });
});

/**
 * The honest limit, asserted so it is documented in behavior and not only in a
 * comment. `(a|a)*` is quadratic — slow, not exponential — and is accepted. The
 * 200-character cap is what keeps that acceptable; a hard guarantee would need
 * a non-backtracking engine.
 */
describe("the documented limit", () => {
  it("accepts star height 1 even when it can be quadratic", () => {
    expect(hasNestedUnboundedQuantifier("(a|a)*")).toBe(false);
  });
});
