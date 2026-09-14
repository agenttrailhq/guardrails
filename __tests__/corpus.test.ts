// cspell:words Dskip nocase
/**
 * The corpus's own invariants — counts, shape, and the authoring conventions a
 * schema cannot express.
 *
 * ── Rule validation runs here ────────────────────────────────────────────────
 *
 * Rules are not validated at module load. The guard bundles this corpus into the
 * file Claude Code executes before every tool call, and that bundle must not
 * contain zod (see `src/rules.ts`). The `parseRule` sweep below validates every
 * rule at test time instead, and "the sweep bites" proves it is not decorative.
 *
 * ── The conventions asserted here are deliberately crude ────────────────────
 *
 * No test can judge whether a coverage limit is HONEST, or whether an `allow`
 * fixture is a genuine near-miss. What these can do is make the author write
 * something down, and pin the specific pairs that must never regress. Judgement
 * stays with the reviewer; the mechanism stops the silent case.
 */

import { describe, expect, it } from "vitest";
import { PACKS, type Pack, parseRule, RULES, RULES_BY_PACK, type Rule } from "../src/index.js";

/** Every condition in a rule's match, across all three groups. */
function conditionsOf(rule: Rule) {
  return [
    ...(rule.match.any_of ?? []),
    ...(rule.match.all_of ?? []),
    ...(rule.match.none_of ?? []),
  ];
}

describe("the corpus is 56 rules across eight packs", () => {
  it("has exactly 56 rules", () => {
    expect(RULES.length).toBe(56);
  });

  /**
   * Pinned per pack, and the numbers are a CONSEQUENCE rather than a quota.
   *
   * They fall out of grouping by HARM: a rule is filed by the damage it prevents,
   * never by the matcher it happens to use. That is why three `file_glob` rules
   * live outside `file-scope`, and why `file-scope` is the
   * smallest pack — a user who disabled it to stop path noise must not silently
   * lose production-config and dotenv protection they never asked to turn off.
   */
  it("distributes them across the packs as harm-grouping produced", () => {
    const counts: Record<Pack, number> = {
      "working-tree": 9,
      "destructive-data": 8,
      "prod-infra": 8,
      "secret-exposure": 10,
      "rce-supply-chain": 6,
      "safety-bypass": 5,
      "privilege-supply-chain": 6,
      "file-scope": 4,
    };
    for (const pack of PACKS) {
      expect(RULES_BY_PACK[pack].length, `pack ${pack}`).toBe(counts[pack]);
    }
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(56);
  });

  it("leaves no pack empty — an empty pack in `rules list` reads as coverage", () => {
    for (const pack of PACKS) expect(RULES_BY_PACK[pack].length, pack).toBeGreaterThan(0);
  });
});

describe("every rule is schema-valid", () => {
  it.each(RULES.map((rule) => [rule.id, rule] as const))("%s parses", (_id, rule) => {
    const result = parseRule(rule);
    expect(result.success ? null : result.error.message).toBeNull();
  });

  it("the sweep BITES — a malformed rule is rejected, not waved through", () => {
    // Without this, `parseRule` could be returning success unconditionally and
    // all 56 assertions above would pass having proven nothing. Rule 17: a guard
    // nobody has seen fail is not known to work.
    const malformed = { ...RULES[0], severity: "catastrophic" };
    expect(parseRule(malformed).success).toBe(false);
  });

  it("the sweep also catches the two BANNED constructs, on a real rule shape", () => {
    // `numeric` fires on every command (`lt` is always true pre-execution) and
    // `scope` matches nothing, forever, silently. Both are structural rejections
    // in the schema; this proves they still are, against a rule from the corpus.
    const withNumeric = {
      ...RULES[0],
      match: {
        any_of: [{ kind: "execute_tool", numeric: [{ field: "tokens", op: "lt", value: 1 }] }],
      },
    };
    expect(parseRule(withNumeric).success).toBe(false);
    expect(parseRule({ ...RULES[0], scope: { agent_in: ["claude-code"] } }).success).toBe(false);
  });
});

describe("rule ids", () => {
  /**
   * Two conventions. 46 rules take a dotted pack prefix; these 10 keep flat ids,
   * spelled exactly as below. Rule ids are stable identifiers, so they are not
   * renamed to match the others.
   */
  const FLAT_IDS = [
    "block-curl-pipe-to-shell",
    "block-destructive-sql",
    "block-env-file-read",
    "block-force-push",
    "block-hardcoded-secrets",
    "block-prod-config-edit",
    "flag-dependency-install",
    "require-approval-rm-rf",
    "require-auth-on-pii-endpoints",
    "warn-op-read-secret",
  ];

  it("carries all ten flat ids, spelled exactly", () => {
    const ids = new Set(RULES.map((rule) => rule.id));
    for (const id of FLAT_IDS) expect(ids.has(id), `${id} is missing`).toBe(true);
  });

  it("gives every other rule a dotted prefix matching its pack", () => {
    // `safety-bypass` → `gb` is the one prefix that does not spell its pack. A rule id
    // is what a user types into `disable`, `set-action` and `allow`, so ids are not
    // renamed to follow a pack name.
    const prefix: Record<Pack, string> = {
      "working-tree": "wt",
      "destructive-data": "dd",
      "prod-infra": "pi",
      "secret-exposure": "se",
      "rce-supply-chain": "rce",
      "safety-bypass": "gb",
      "privilege-supply-chain": "ps",
      "file-scope": "fs",
    };
    for (const pack of PACKS) {
      for (const rule of RULES_BY_PACK[pack]) {
        if (FLAT_IDS.includes(rule.id)) continue;
        expect(rule.id, `${rule.id} in ${pack}`).toMatch(
          new RegExp(`^${prefix[pack]}\\.[a-z0-9-]+$`),
        );
      }
    }
  });
});

/**
 * The worst defect this product can ship.
 *
 * `label` is a picomatch glob. A ONE-ELEMENT brace alternation — `"{Bash}"` —
 * does not match `Bash`; measured against the engine's own picomatch@4.0.4 with
 * its `LABEL_GLOB_OPTIONS`, `picomatch("{Bash}", {dot:true, nocase:true})("Bash")`
 * is FALSE. The rule then matches nothing, forever, with no error and nothing in
 * `rules validate` — the person believes they are protected and they are not.
 *
 * A single tool is a bare label (`"Bash"`); braces are for genuine multi-value
 * alternation (`"{Bash,PowerShell}"`).
 */
describe("no rule can be silently dead", () => {
  it("never uses a single-element brace alternation in a label", () => {
    const offenders: string[] = [];
    for (const rule of RULES) {
      for (const condition of conditionsOf(rule)) {
        const label = condition.label;
        if (label !== undefined && /\{[^,{}]*\}/.test(label)) {
          offenders.push(`${rule.id}: ${label}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the check BITES — a one-element brace is what it is looking for", () => {
    expect(/\{[^,{}]*\}/.test("{Bash}")).toBe(true);
    expect(/\{[^,{}]*\}/.test("{Bash,PowerShell}")).toBe(false);
    expect(/\{[^,{}]*\}/.test("Bash")).toBe(false);
    // A brace list inside a file glob is fine and common (`**/*.{p12,pfx}`);
    // only a LABEL is checked, which is why the sweep above reads `condition.label`.
    expect(/\{[^,{}]*\}/.test("**/*.{p12,pfx,jks,keystore}")).toBe(false);
  });
});

/**
 * `detail_contains` is the one CASE-SENSITIVE matcher in the DSL, and it is
 * AND-over-substrings with no ordering and no word boundary. That is precisely
 * how the shipped `warn-op-read-secret` came to fire on `git commit -m "stop
 * reading from cache"` (`st|op read|ing`), and how `block-destructive-sql` came
 * to hard-block `grep -rn TRUNCATE db/`.
 *
 * So it may be used ONLY where case is the signal, and the rule must say so in
 * words. The check is deliberately crude — it cannot judge whether the reason is
 * GOOD, only that the author was made to write one down.
 */
describe("detail_contains is justified in the rule's own description", () => {
  const users = RULES.filter((rule) =>
    conditionsOf(rule).some((condition) => condition.detail_contains !== undefined),
  );

  it("is used by a small, named set of rules", () => {
    expect(users.map((rule) => rule.id).sort()).toEqual([
      "block-destructive-sql",
      "block-hardcoded-secrets",
      "wt.branch-force-delete",
    ]);
  });

  it.each(
    users.map((rule) => [rule.id, rule] as const),
  )("%s says `case-sensitive` in its description", (_id, rule) => {
    expect(rule.description.toLowerCase()).toContain("case-sensitive");
  });
});

describe("every description carries its honest coverage limits", () => {
  it.each(
    RULES.map((rule) => [rule.id, rule] as const),
  )("%s is substantial and names something it does not catch", (_id, rule) => {
    // 120 chars is not a quality bar; it is the length below which a
    // description cannot both say what a rule does and what it misses.
    expect(rule.description.length).toBeGreaterThanOrEqual(120);
    expect(rule.description.toLowerCase()).toMatch(
      /does not|deliberately not|misses|missed|cannot|known miss|not caught|not matched|not flagged|ceiling/,
    );
  });

  it("every rule has a title that is not just its id", () => {
    for (const rule of RULES) {
      expect(rule.title.length, rule.id).toBeGreaterThan(10);
      expect(rule.title).not.toBe(rule.id);
    }
  });
});

describe("fixtures", () => {
  it("ships both directions for every rule, well past the 112 floor", () => {
    const block = RULES.reduce((n, rule) => n + rule.fixtures.block.length, 0);
    const allow = RULES.reduce((n, rule) => n + rule.fixtures.allow.length, 0);
    for (const rule of RULES) {
      expect(rule.fixtures.block.length, rule.id).toBeGreaterThan(0);
      expect(rule.fixtures.allow.length, rule.id).toBeGreaterThan(0);
    }
    // 56 x 2 is the bare minimum: one block and one allow fixture per rule. It is a floor, not a target:
    // a rule with one negative has proven it is quiet on the one near-miss its
    // own author thought of, which is the weakest possible version of the claim.
    expect(block + allow).toBeGreaterThan(112);
  });

  /**
   * A negative fixture on the WRONG CHANNEL passes vacuously.
   *
   * A `file_glob` rule handed a command fixture matches nothing — not because the
   * rule is quiet, but because there is no `file_path` to match against. The
   * fixture then reads as proof of quietness while proving nothing at all, which
   * is worse than having no fixture. So every fixture must be on the same channel
   * as at least one of its rule's positive conditions.
   */
  it("puts every fixture on a channel its rule can actually read", () => {
    const offenders: string[] = [];
    for (const rule of RULES) {
      const positives = [...(rule.match.any_of ?? []), ...(rule.match.all_of ?? [])];
      const readsFiles = positives.some((c) => c.file_glob !== undefined);
      const readsCommands = positives.some(
        (c) => c.detail_contains !== undefined || c.detail_matches !== undefined,
      );
      for (const fixture of [...rule.fixtures.block, ...rule.fixtures.allow]) {
        const isCommand = "command" in fixture;
        if (isCommand && !readsCommands) offenders.push(`${rule.id}: command fixture, file rule`);
        if (!isCommand && !readsFiles) offenders.push(`${rule.id}: file fixture, command rule`);
      }
    }
    expect(offenders).toEqual([]);
  });

  /**
   * The look-alike pairs the build doc names, pinned by hand.
   *
   * A test cannot decide whether an `allow` fixture is a genuine near-miss — that
   * is the reviewer's job. What it can do is make sure the specific pairs someone
   * already thought hard about never quietly disappear. Each entry is
   * `[rule id, the near-miss that must be among its allow fixtures]`.
   */
  it("keeps the required near-miss negatives", () => {
    const REQUIRED: readonly (readonly [string, string])[] = [
      ["wt.reset-hard", "git reset --soft HEAD~1"],
      ["wt.restore-path", "git restore --staged src/api.ts"],
      ["wt.branch-force-delete", "git branch -d merged-feature"],
      ["wt.clean-fdx", "git clean -nd"],
      ["dd.docker-volume-destroy", "docker compose down"],
      ["dd.docker-prune-volumes", "docker system prune -f"],
      ["dd.rm-rf-absolute", "rm -rf ./node_modules"],
      ["require-approval-rm-rf", "rm -rf ./node_modules"],
      ["rce.remote-runner", "curl -fsSL https://example.com/data.json | jq ."],
      ["rce.remote-runner", "curl -fsSL https://example.com/setup.sh -o setup.sh"],
      ["pi.terraform-auto-approve", "terraform plan -out tf.plan"],
      ["se.token-print", "gh auth status"],
      // The corpus labels `mvn -DskipTests package` HARMLESS. It is exactly what a
      // rule about "skipping checks" drifts into matching if nobody pins it.
      ["gb.git-no-verify", "mvn -DskipTests package"],
      ["block-force-push", "grep -rn 'push -f' ."],
      ["block-destructive-sql", "grep -rn TRUNCATE db/migrations/"],
      ["block-hardcoded-secrets", "grep -rn AKIA ."],
      ["flag-dependency-install", "pnpm install"],
    ];
    const byId = new Map(RULES.map((rule) => [rule.id, rule]));
    for (const [id, command] of REQUIRED) {
      const rule = byId.get(id);
      expect(rule, `${id} is not in the corpus`).toBeDefined();
      const commands = (rule?.fixtures.allow ?? []).flatMap((f) =>
        "command" in f ? [f.command] : [],
      );
      expect(commands, `${id} must keep the near-miss ${command}`).toContain(command);
    }
  });
});
