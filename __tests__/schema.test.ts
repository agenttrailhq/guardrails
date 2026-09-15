// cspell:words exfil
/**
 * Rule-schema invariants.
 *
 * These use only this package's own schema, not the evaluator. "Does this rule
 * actually fire?" is answered by running its fixtures through the evaluator,
 * which is not part of this package.
 */

import { describe, expect, it } from "vitest";
import {
  DETAIL_MATCHES_MAX_PATTERN_LENGTH,
  DETAIL_MATCHES_MAX_PATTERNS,
  defineRule,
  parseRule,
  parseRuleOrThrow,
  type RuleInput,
  SEVERITIES,
} from "../src/index.js";

/**
 * A complete example rule. If this stops parsing, the published format has changed.
 */
const SPEC_EXAMPLE: RuleInput = {
  id: "wt.reset-hard",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "git reset --hard discards uncommitted work",
  description:
    "Discards all uncommitted changes. Does not match `git restore` — see wt.restore-path.",
  match: {
    any_of: [
      { kind: "execute_tool", label: "Bash", detail_matches: ["\\bgit\\s+reset\\s+--hard\\b"] },
    ],
  },
  fixtures: {
    block: ["git reset --hard", { tool: "PowerShell", command: "git reset --hard" }],
    allow: ["git reset src/api.ts", { tool: "Read", file_path: "src/api.ts" }],
  },
};

/** A minimal valid rule, so a test can vary exactly one thing. */
function ruleWith(overrides: Partial<RuleInput> = {}): RuleInput {
  return {
    id: "wt.example",
    category: "working-tree",
    severity: "high",
    defaultAction: "block",
    title: "Example",
    description: "Example rule. Misses nothing, because it catches nothing.",
    match: { any_of: [{ kind: "execute_tool", label: "Bash", detail_contains: ["danger"] }] },
    fixtures: { block: ["danger"], allow: ["safe"] },
    ...overrides,
  };
}

describe("the documented example rule", () => {
  it("parses", () => {
    const result = parseRule(SPEC_EXAMPLE);
    expect(result.success).toBe(true);
  });

  it("normalizes its bare-string fixtures to the Bash command channel", () => {
    const result = parseRule(SPEC_EXAMPLE);
    if (!result.success) throw new Error("expected the example rule to parse");
    expect(result.data.fixtures.block[0]).toEqual({ tool: "Bash", command: "git reset --hard" });
    expect(result.data.fixtures.allow[0]).toEqual({
      tool: "Bash",
      command: "git reset src/api.ts",
    });
  });

  it("keeps a tagged fixture's own tool and channel", () => {
    const result = parseRule(SPEC_EXAMPLE);
    if (!result.success) throw new Error("expected the example rule to parse");
    expect(result.data.fixtures.block[1]).toEqual({
      tool: "PowerShell",
      command: "git reset --hard",
    });
    expect(result.data.fixtures.allow[1]).toEqual({ tool: "Read", file_path: "src/api.ts" });
  });
});

describe("severity", () => {
  it("is exactly the product's five values, in order", () => {
    expect(SEVERITIES).toEqual(["critical", "high", "medium", "low", "info"]);
  });

  it.each(SEVERITIES)("accepts %s", (severity) => {
    expect(parseRule(ruleWith({ severity })).success).toBe(true);
  });

  it("is required — a rule without one does not parse", () => {
    const { severity: _dropped, ...withoutSeverity } = ruleWith();
    expect(parseRule(withoutSeverity).success).toBe(false);
  });

  it("rejects a value outside the five", () => {
    expect(parseRule(ruleWith({ severity: "catastrophic" as never })).success).toBe(false);
  });
});

describe("undeclared metadata keys are rejected", () => {
  it("rejects minTier", () => {
    const result = parseRule({ ...ruleWith(), minTier: "Business" });
    expect(result.success).toBe(false);
  });

  it("rejects installCount", () => {
    const result = parseRule({ ...ruleWith(), installCount: 1247 });
    expect(result.success).toBe(false);
  });

  it("rejects any unknown key", () => {
    expect(parseRule({ ...ruleWith(), riskUsd: 320_000 }).success).toBe(false);
  });
});

describe("fixture channels", () => {
  it("accepts a bare string as Bash-command shorthand", () => {
    const result = parseRule(ruleWith({ fixtures: { block: ["rm -rf /"], allow: ["ls"] } }));
    if (!result.success) throw new Error("expected shorthand to parse");
    expect(result.data.fixtures.block).toEqual([{ tool: "Bash", command: "rm -rf /" }]);
  });

  it("accepts the command channel from a non-Bash tool (PowerShell)", () => {
    const fixtures = {
      block: [{ tool: "PowerShell", command: "Remove-Item -Recurse -Force C:\\" }],
      allow: [{ tool: "PowerShell", command: "Get-ChildItem" }],
    };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(true);
  });

  it("accepts the file channel (the file-scope pack's only channel)", () => {
    const fixtures = {
      block: [{ tool: "Edit", file_path: "config/.env.production" }],
      allow: [{ tool: "Edit", file_path: "src/index.ts" }],
    };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(true);
  });

  it("accepts a WebSearch query on the command channel", () => {
    const fixtures = {
      block: [{ tool: "WebSearch", command: "how to disable audit logging" }],
      allow: [{ tool: "WebSearch", command: "typescript generics" }],
    };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(true);
  });

  it("requires a tool on the object form", () => {
    const fixtures = { block: [{ command: "rm -rf /" }], allow: ["ls"] };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects a fixture carrying no channel", () => {
    const fixtures = { block: [{ tool: "Bash" }], allow: ["ls"] };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects a fixture carrying BOTH channels — exactly one, or it is ambiguous", () => {
    const fixtures = {
      block: [{ tool: "Bash", command: "rm -rf /", file_path: "src/index.ts" }],
      allow: ["ls"],
    };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects an empty command string, which would match everything or nothing", () => {
    const fixtures = { block: [""], allow: ["ls"] };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(false);
  });
});

/**
 * A `{ tool: "WebFetch", url: … }` fixture. The evaluator reads only `detail` and
 * `file_path`, so a URL fixture would exercise a field nothing reads. It must FAIL
 * LOUDLY rather than parse into a fixture that tests nothing.
 */
describe("there is no url channel", () => {
  it("rejects a WebFetch url fixture outright", () => {
    const fixtures = {
      block: [{ tool: "WebFetch", url: "https://evil.example.com/exfil" }],
      allow: [{ tool: "WebFetch", url: "https://docs.example.com" }],
    };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects url smuggled alongside a valid channel", () => {
    const fixtures = {
      block: [{ tool: "WebFetch", command: "fetch", url: "https://evil.example.com" }],
      allow: ["ls"],
    };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });
});

describe("both fixture directions are required", () => {
  it("rejects a rule with no allow fixture — the negative is the one that proves quietness", () => {
    const fixtures = { block: ["rm -rf /"], allow: [] };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(false);
  });

  it("rejects a rule with no block fixture", () => {
    const fixtures = { block: [], allow: ["ls"] };
    expect(parseRule(ruleWith({ fixtures })).success).toBe(false);
  });

  it("rejects a rule missing the allow key entirely", () => {
    const fixtures = { block: ["rm -rf /"] };
    expect(parseRule(ruleWith({ fixtures } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects a rule with no fixtures at all", () => {
    const { fixtures: _dropped, ...withoutFixtures } = ruleWith();
    expect(parseRule(withoutFixtures).success).toBe(false);
  });
});

describe("match composition", () => {
  it("accepts all_of", () => {
    const match = { all_of: [{ kind: "execute_tool", detail_contains: ["git"] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(true);
  });

  it("accepts none_of as a refinement on a positive selector", () => {
    const match = {
      any_of: [{ kind: "execute_tool", detail_contains: ["rm -rf"] }],
      none_of: [{ kind: "execute_tool", detail_contains: ["node_modules"] }],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(true);
  });

  it("rejects none_of standing alone — at block it would deny everything", () => {
    const match = { none_of: [{ kind: "execute_tool", detail_contains: ["safe"] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it("rejects an empty match", () => {
    expect(parseRule(ruleWith({ match: {} })).success).toBe(false);
  });

  it("rejects an unknown composition key", () => {
    const match = { any_of: [{ kind: "execute_tool" }], some_of: [{ kind: "execute_tool" }] };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("requires kind on a condition", () => {
    const match = { any_of: [{ label: "Bash", detail_contains: ["rm"] }] };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });
});

describe("detail_matches regex limits", () => {
  it("rejects a pattern that does not compile", () => {
    const match = { any_of: [{ kind: "execute_tool", detail_matches: ["([unclosed"] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it.each([
    ["(a+)+"],
    ["(a*)*"],
    ["(\\s+x?)+"],
  ])("rejects the nested unbounded quantifier %s — the guard fails open, so backtracking disables it", (pattern) => {
    const match = { any_of: [{ kind: "execute_tool", detail_matches: [pattern] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it("accepts an ordinary bounded pattern", () => {
    const match = { any_of: [{ kind: "execute_tool", detail_matches: ["\\bgit\\s+push\\b"] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(true);
  });

  it(`rejects a pattern longer than ${DETAIL_MATCHES_MAX_PATTERN_LENGTH}`, () => {
    const match = {
      any_of: [
        {
          kind: "execute_tool",
          detail_matches: ["a".repeat(DETAIL_MATCHES_MAX_PATTERN_LENGTH + 1)],
        },
      ],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it(`rejects more than ${DETAIL_MATCHES_MAX_PATTERNS} patterns on one condition`, () => {
    const match = {
      any_of: [
        {
          kind: "execute_tool",
          detail_matches: Array.from(
            { length: DETAIL_MATCHES_MAX_PATTERNS + 1 },
            (_, i) => `p${i}`,
          ),
        },
      ],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });
});

describe("required text fields", () => {
  it.each(["id", "category", "title", "description"] as const)("rejects an empty %s", (field) => {
    expect(parseRule(ruleWith({ [field]: "" })).success).toBe(false);
  });

  it("rejects an action outside block / require_approval / warn", () => {
    expect(parseRule(ruleWith({ defaultAction: "ask" as never })).success).toBe(false);
  });
});

/**
 * `defineRule` is how every rule is authored, so its failure path is the
 * one that decides whether a malformed rule reaches the registry or stops at
 * import. An unvalidated authoring helper is how a corpus quietly acquires a
 * rule that never fires.
 */
describe("the authoring entry point", () => {
  it("defineRule returns the parsed, normalized rule", () => {
    const rule = defineRule(ruleWith({ fixtures: { block: ["danger"], allow: ["safe"] } }));
    expect(rule.id).toBe("wt.example");
    expect(rule.fixtures.block).toEqual([{ tool: "Bash", command: "danger" }]);
  });

  it("defineRule throws at import time on a malformed rule", () => {
    expect(() => defineRule({ ...ruleWith(), severity: "catastrophic" as never })).toThrow(
      /invalid guardrails rule wt\.example/,
    );
  });

  it("names the offending rule id in the error, so the failure points somewhere", () => {
    expect(() =>
      defineRule({ ...ruleWith({ id: "dd.drop-table" }), defaultAction: "ask" as never }),
    ).toThrow(/dd\.drop-table/);
  });

  it("falls back to a placeholder id when the input has none", () => {
    expect(() => parseRuleOrThrow({ not: "a rule" })).toThrow(/<unknown id>/);
  });

  it("parseRuleOrThrow rejects a non-object outright", () => {
    expect(() => parseRuleOrThrow("git reset --hard")).toThrow(/<unknown id>/);
    expect(() => parseRuleOrThrow(null)).toThrow(/<unknown id>/);
  });

  it("parseRuleOrThrow returns the rule on success", () => {
    expect(parseRuleOrThrow(SPEC_EXAMPLE).id).toBe("wt.reset-hard");
  });
});
