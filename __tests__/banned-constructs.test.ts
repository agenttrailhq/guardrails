/**
 * The three banned constructs, enforced by a test that fails the build.
 *
 * All three share one failure mode, and it is the worst one a security tool has:
 * they produce a rule that **looks enforced and is not**. Nothing errors, the
 * rule appears in `status`, and it never fires — or, in the numeric case, fires
 * on everything.
 *
 * Two of the three are rejected structurally (a key the `.strict()` schema does
 * not declare); the third needs a real refinement. These tests are the
 * regression guard on all three: if someone later adds `numeric` to the
 * condition schema to mirror the engine more closely, or relaxes the
 * command-plus-file refinement, this file goes red and says why.
 */

import { describe, expect, it } from "vitest";
import { parseRule, type RuleInput } from "../src/index.js";

function ruleWith(overrides: Partial<RuleInput> = {}): RuleInput {
  return {
    id: "wt.example",
    category: "working-tree",
    severity: "high",
    defaultAction: "block",
    title: "Example",
    description: "Example rule.",
    match: { any_of: [{ kind: "execute_tool", label: "Bash", detail_contains: ["danger"] }] },
    fixtures: { block: ["danger"], allow: ["safe"] },
    ...overrides,
  };
}

/** Parse and return the concatenated issue messages, for asserting on the reason. */
function reasonFor(rule: unknown): string {
  const result = parseRule(rule);
  if (result.success) throw new Error("expected this rule to be rejected, but it parsed");
  return result.error.issues.map((issue) => issue.message).join(" | ");
}

/**
 * `scope.agent_in` compares literally against an agent id that is always a UUID
 * — never the vendor string "claude-code". A scoped rule matches nothing,
 * forever, silently.
 */
describe("ban 1: scope", () => {
  it("rejects scope on the rule envelope", () => {
    expect(parseRule({ ...ruleWith(), scope: { agent_in: ["claude-code"] } }).success).toBe(false);
  });

  it("rejects scope smuggled inside match", () => {
    const match = {
      any_of: [{ kind: "execute_tool", detail_contains: ["rm"] }],
      scope: { agent_in: ["claude-code"] },
    };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects scope on an individual condition", () => {
    const match = { any_of: [{ kind: "execute_tool", scope: { project_in: ["my-project"] } }] };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });
});

/**
 * At guard decision time the action has NOT run, so `tokens`, `cached_tokens`
 * and `duration_ms` are all 0. `gt` is therefore always false — the rule can
 * never block — and `lt` is always true, so the rule fires on every command.
 * The second is the dangerous one: a "block anything under 100 tokens" rule
 * denies everything the agent tries to do.
 */
describe("ban 2: numeric conditions", () => {
  it("rejects a numeric condition", () => {
    const match = {
      any_of: [{ kind: "execute_tool", numeric: [{ field: "tokens", op: "gt", value: 1000 }] }],
    };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects the `lt` form specifically — always true, so it fires on everything", () => {
    const match = {
      any_of: [{ kind: "execute_tool", numeric: [{ field: "duration_ms", op: "lt", value: 5 }] }],
    };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });

  it("rejects numeric even alongside an otherwise valid matcher", () => {
    const match = {
      any_of: [
        {
          kind: "execute_tool",
          detail_contains: ["rm -rf"],
          numeric: [{ field: "cached_tokens", op: "gte", value: 1 }],
        },
      ],
    };
    expect(parseRule(ruleWith({ match } as unknown as Partial<RuleInput>)).success).toBe(false);
  });
});

/**
 * The guard's mapper is an if/else chain: a tool call carries a command OR a
 * file path, never both. A condition demanding both can never be satisfied.
 *
 * Unlike the first two bans this one is not structural — both keys are
 * individually legal — so it needs a refinement, and the refinement needs its
 * own regression test.
 */
describe("ban 3: a command matcher and a file matcher in one condition", () => {
  it("rejects detail_contains + file_glob", () => {
    const match = {
      any_of: [{ kind: "execute_tool", detail_contains: ["rm -rf"], file_glob: "**/*.env" }],
    };
    const reason = reasonFor(ruleWith({ match }));
    expect(reason).toMatch(/may not combine a command matcher/i);
  });

  it("rejects detail_matches + file_glob", () => {
    const match = {
      any_of: [{ kind: "execute_tool", detail_matches: ["\\brm\\b"], file_glob: "**/*.env" }],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it("rejects the combination inside none_of too, not just the positive arms", () => {
    const match = {
      any_of: [{ kind: "execute_tool", detail_contains: ["rm -rf"] }],
      none_of: [{ kind: "execute_tool", detail_contains: ["tmp"], file_glob: "**/tmp/**" }],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(false);
  });

  it("accepts a command matcher alone", () => {
    const match = { any_of: [{ kind: "execute_tool", detail_contains: ["rm -rf"] }] };
    expect(parseRule(ruleWith({ match })).success).toBe(true);
  });

  it("accepts a file matcher alone", () => {
    const match = { any_of: [{ kind: "execute_tool", file_glob: "**/.env*" }] };
    expect(
      parseRule(
        ruleWith({
          match,
          fixtures: {
            block: [{ tool: "Read", file_path: ".env" }],
            allow: [{ tool: "Read", file_path: "src/index.ts" }],
          },
        }),
      ).success,
    ).toBe(true);
  });

  it("accepts the two as SEPARATE conditions under any_of — the documented fix", () => {
    const match = {
      any_of: [
        { kind: "execute_tool", detail_contains: ["rm -rf"] },
        { kind: "execute_tool", file_glob: "**/.env*" },
      ],
    };
    expect(parseRule(ruleWith({ match })).success).toBe(true);
  });
});
