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
import { hasNestedUnboundedQuantifier, RULES } from "../src/index.js";

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
 * length cap (`DETAIL_MATCHES_MAX_PATTERN_LENGTH`) is what keeps that acceptable; a
 * hard guarantee would need a non-backtracking engine.
 */
describe("the documented limit", () => {
  it("accepts star height 1 even when it can be quadratic", () => {
    expect(hasNestedUnboundedQuantifier("(a|a)*")).toBe(false);
  });
});

/**
 * The guardrails that scan every argument of a command repeat a bounded group of
 * arguments, which star height 1 allows but which could still be slow on a long
 * command. Each of their patterns is timed on long inputs that match nothing, the case
 * that makes a backtracking engine try every split.
 */
describe("argument-scanning patterns stay fast on long commands", () => {
  const SCANNING_RULES = [
    "dd.rm-rf-absolute",
    "require-approval-rm-rf",
    "block-force-push",
    // The temp-folder delete exemption, the tunnel command position and the SQL client lookahead.
    "ti.test-file-delete",
    "ex.tunnel-expose",
    "block-destructive-sql",
    // Quoted and escaped spellings, the hook and self-config shapes, and the decode pipes.
    "gb.git-no-verify",
    "gb.hooks-disable",
    "gb.agenttrail-disable",
    "fs.agent-self-config",
    "rce.decode-to-shell",
  ];
  const patterns = RULES.filter((rule) => SCANNING_RULES.includes(rule.id)).flatMap((rule) =>
    [...(rule.match.any_of ?? []), ...(rule.match.none_of ?? [])].flatMap(
      (c) => c.detail_matches ?? [],
    ),
  );
  const repeat = (word: string, n: number) => Array.from({ length: n }, () => word).join(" ");
  const inputs = [
    `rm ${repeat("-v", 400)}`,
    `rm ${repeat("abcdef", 600)}`,
    `rm ${repeat("-x", 300)} /`,
    `rm -rf ${repeat("node_modules", 300)} x`,
    `git push ${repeat("-x", 600)}`,
    `git rm ${repeat("a", 900)} --cached;`,
    // A pattern that scans to the end of the input from each `git push` grows with the
    // square of the length. 8192 characters is the longest command the hook passes on.
    "git push x ".repeat(745).slice(0, 8192),
    // Temp-folder targets that almost qualify: deep paths, many targets, a bad last character.
    `rm -rf /tmp/${repeat("a", 2000).replaceAll(" ", "/")};`,
    `rm -rf ${repeat("/tmp/a/b", 600)} $X`,
    `rm -rf ${repeat("$TMPDIR/a/..", 400)}`,
    // Wrapper words and separators with no tunnel tool after them.
    `${repeat("sudo env A=1 timeout 9", 300)} ngrok`,
    `${repeat(";", 4000)} x`,
    // Long text with SQL phrases and no client, and a client with no phrase.
    `${repeat("drop table x", 600)}`,
    `psql ${repeat("drop tables", 600)}`,
    // Quotes, IFS separators, brace items and backslash continuations with no target.
    `rm ${"'".repeat(4000)}`,
    `rm${"$IFS-x".repeat(700)}`,
    `{rm,${repeat("a,", 2000)}`,
    `git commit ${repeat('"a"', 1000)}`,
    `git -c ${"\\\n".repeat(2000)}`,
    `git -c ${"core".repeat(1000)}`,
    // Decoders and wrappers with no shell at the end, and long blanks before the shell word.
    `base64 -d ${repeat("| cat", 800)}`,
    `base64 -d | ${repeat("sudo -x", 500)}`,
    `base64 -d x |${" ".repeat(8000)}x`,
    // The HTTP carrier's write-flag check: many quoted arguments, and many flags after a body.
    `curl ${repeat('"a"', 2000)}`,
    `curl -d "x" ${repeat("-o x", 1500)}`,
    `wget -d "x" ${repeat(`-'x'"`, 1500)}`,
    `curl -d "x" ${repeat("-o /dev/null", 700)} $X`,
    // Long decoder arguments and many stages, which the 999-character spans read.
    `base64 ${repeat("-w0", 2700)}`,
    `base64 -d ${repeat("| cat", 1600)}`,
    `${"$(base64 -d ".repeat(600)}`,
    `${"( ".repeat(4000)}base64 -d`,
    // Protected folders with no write, and long names that almost obfuscate a path.
    `> ~/.${"x".repeat(4000)}`,
    `cd .claude && ${repeat("x", 2000)}`,
    `find .claude ${repeat("-x", 1500)}`,
    `agenttrail-guard ${repeat("-x", 1500)}`,
    // Quoted paths and globs under a protected folder that name no protected file.
    `echo x > ${repeat('".claude/a"', 700)}`,
    `cp x .claude/${"a*".repeat(4000)}.md`,
    // Nested substitutions with no decoder at the end.
    `${"$(".repeat(4000)}base64 -d`,
  ];

  it("finds the patterns it times", () => {
    expect(patterns.length).toBeGreaterThanOrEqual(10);
  });

  // Compiled once, as the guard compiles each pattern once; only matching is timed. V8 builds a
  // pattern's matcher on its first use, so each is used once here before any timing. The best of
  // three runs is kept: a backtracking pattern is slow every time, while a busy test runner
  // (the files run in parallel) only slows some runs.
  const compiled = patterns.map((source) => new RegExp(source, "i"));
  for (const re of compiled) re.test("");

  it.each(inputs.map((input) => [input.slice(0, 24), input]))("%s… under 50 ms", (_l, input) => {
    let best = Number.POSITIVE_INFINITY;
    for (let run = 0; run < 3; run++) {
      const start = performance.now();
      for (const re of compiled) re.test(input);
      best = Math.min(best, performance.now() - start);
    }
    expect(best).toBeLessThan(50);
  });
});

/**
 * A long run of whitespace, read by every pattern in the corpus.
 *
 * A start alternative that can match inside a run (a newline) followed by its own `\s*` makes
 * each start re-read the rest of the run: quadratic in its length. Every pattern must give the
 * run one owner, so each one stays fast on a 50,000-character run of newlines or blanks.
 */
describe("every pattern is linear on a long run of whitespace", () => {
  const compiled = RULES.flatMap((rule) =>
    [...(rule.match.any_of ?? []), ...(rule.match.all_of ?? []), ...(rule.match.none_of ?? [])]
      .flatMap((c) => c.detail_matches ?? [])
      .map((source) => ({ id: rule.id, re: new RegExp(source, "i") })),
  );
  for (const { re } of compiled) re.test("");
  const runs = [
    ["newlines", "\n".repeat(50_000)],
    ["newlines then a word", `${"\n".repeat(50_000)}x`],
    ["blanks", " ".repeat(50_000)],
    ["newline and blank", "\n ".repeat(25_000)],
    ["CRLF", "\r\n".repeat(25_000)],
    ["separator and blank", "; ".repeat(25_000)],
  ] as const;

  it.each(runs)("%s: each pattern under 50 ms", (_name, input) => {
    for (const { id, re } of compiled) {
      const start = performance.now();
      re.test(input);
      expect(performance.now() - start, id).toBeLessThan(50);
    }
  });
});
