/**
 * The guardrails rule format — self-contained, and deliberately so.
 *
 * This file defines the rule format and imports nothing but zod, so the package
 * builds on its own. The condition and match shapes mirror the evaluator's rather
 * than importing them; a change to either has to be made in both places.
 *
 * A rule carries `defaultAction` (what the guard does when it matches) and no
 * `version`; the package version is the corpus version.
 */

import { z } from "zod";

// ── Severity ────────────────────────────────────────────────────────────────

/**
 * The five severities, in order, most→least severe.
 *
 * `info` earns its place: five of the eight packs default to `ask`/`warn`, and a
 * warn-only rule labelled `low` overstates itself.
 *
 * Severity says how serious a match is. This package maps it to nothing else,
 * including cost: the guard prints no currency.
 */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

/** How dangerous the thing a rule catches is. An authoring signal, not a price. */
export const SeveritySchema = z.enum(SEVERITIES);

// ── Actions ─────────────────────────────────────────────────────────────────

/**
 * What the guard does when a rule matches.
 *
 * The guard maps these onto Claude Code's `PreToolUse` verdicts:
 * `block` → deny, `require_approval` → ask, `warn` → allow-but-recorded.
 */
export const ACTIONS = ["block", "require_approval", "warn"] as const;

/** The action a rule takes by default, before any user override. */
export const ActionSchema = z.enum(ACTIONS);

// ── detail_matches: regex limits, mirrored from the engine ───────────────────

/** Longest accepted `detail_matches` pattern. Long enough for any real rule. */
export const DETAIL_MATCHES_MAX_PATTERN_LENGTH = 200;

/** Most `detail_matches` patterns allowed on one condition (they are ORed). */
export const DETAIL_MATCHES_MAX_PATTERNS = 10;

/**
 * Reject a regex that can backtrack catastrophically, at PARSE time.
 *
 * Node has no regex timeout, so the only real bounds are a non-backtracking
 * engine (RE2 — a runtime dependency deliberately not taken) or a syntactic
 * restriction. This is the syntactic one: it rejects **star height >= 2**, an
 * unbounded quantifier applied to a group that itself contains an unbounded
 * quantifier — `(a+)+`, `(a*)*`, `(\s+x?)+` — the shape behind essentially every
 * practical ReDoS.
 *
 * The guard's hook has a 10s Claude Code timeout, no internal watchdog, and it
 * **fails open**: a pattern that backtracks does not merely make enforcement slow,
 * it lets the action through. A slow rule in the guard is a disabled rule.
 *
 * HONEST LIMIT: this is a bound, not a proof. Star height 1 can still be
 * quadratic (`(a|a)*`), which is slow but not exponential, and is acceptable
 * against the length cap above. A hard guarantee needs RE2.
 *
 * @param source - The regex body (no delimiters, no flags).
 * @returns `true` when the pattern nests unbounded quantifiers.
 */
export function hasNestedUnboundedQuantifier(source: string): boolean {
  /** Is `source[i]` an unbounded quantifier (`*`, `+`, or `{n,}`)? */
  const unboundedQuantifierAt = (s: string, i: number): boolean => {
    const ch = s[i];
    if (ch === "*" || ch === "+") return true;
    if (ch !== "{") return false;
    const close = s.indexOf("}", i);
    // `{n,}` is unbounded; `{n}` and `{n,m}` are not.
    return close !== -1 && /^\{\d*,\}$/.test(s.slice(i, close + 1));
  };

  /** Does `body` contain an unbounded quantifier outside a character class? */
  const containsUnbounded = (body: string): boolean => {
    let inClass = false;
    for (let i = 0; i < body.length; i++) {
      const ch = body[i];
      if (ch === "\\") {
        i++;
        continue;
      }
      if (inClass) {
        if (ch === "]") inClass = false;
        continue;
      }
      if (ch === "[") {
        inClass = true;
        continue;
      }
      if (unboundedQuantifierAt(body, i)) return true;
    }
    return false;
  };

  const groupStarts: number[] = [];
  let inClass = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (ch === "\\") {
      i++; // skip the escaped char — `\(` is a literal, not a group
      continue;
    }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      continue;
    }
    if (ch === "(") {
      groupStarts.push(i);
      continue;
    }
    if (ch === ")") {
      const start = groupStarts.pop();
      if (start === undefined) continue; // unbalanced — the RegExp compile catches it
      // Quantified group? Then its body must not itself repeat unboundedly.
      if (unboundedQuantifierAt(source, i + 1) && containsUnbounded(source.slice(start + 1, i))) {
        return true;
      }
    }
  }
  return false;
}

/**
 * One `detail_matches` pattern: compilable, length-capped, and free of nested
 * unbounded quantifiers. The engine compiles these with `i` and never `g`/`y` —
 * a global regex carries `lastIndex` between calls and would intermittently miss.
 */
const DetailMatchPatternSchema = z
  .string()
  .min(1)
  .max(DETAIL_MATCHES_MAX_PATTERN_LENGTH)
  .superRefine((pattern, ctx) => {
    try {
      new RegExp(pattern, "i");
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `detail_matches: not a valid regular expression (${
          error instanceof Error ? error.message : "unknown error"
        })`,
      });
      return;
    }
    if (hasNestedUnboundedQuantifier(pattern)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "detail_matches: nested unbounded quantifier (e.g. `(a+)+`) can backtrack catastrophically; rewrite without repeating a repeating group",
      });
    }
  });

// ── Match conditions ────────────────────────────────────────────────────────

/**
 * One condition matched against a tool call.
 *
 * - `kind`: required. The span kind, e.g. `execute_tool`. Case-insensitive.
 * - `label`: optional. The tool name — a case-insensitive GLOB, so
 *   `mcp__chrome__*` and `{Bash,PowerShell}` are one condition rather than a
 *   list that rots. A plain label has no glob character and matches exactly.
 * - `detail_contains`: optional. Substrings that must ALL appear (AND).
 *   **CASE-SENSITIVE**, and deliberately: `AKIA`, `ghp_`, `sk_live_` and the
 *   upper-case `TRUNCATE` arm are rules where case IS the signal. Author
 *   case-insensitive text matches with `detail_matches` instead.
 * - `detail_matches`: optional. Regex patterns against the same text; at least
 *   one must match (OR, unlike `detail_contains`). Case-insensitive.
 * - `file_glob`: optional. Case-insensitive glob against the file path.
 *
 * ── Two engine fields are deliberately absent ────────────────────────────────
 *
 * `numeric` is BANNED. At guard decision time `tokens`,
 * `cachedTokens` and `durationMs` are all 0, because the action has not run yet.
 * `gt` is therefore always false — the rule can never fire — and, worse, **`lt`
 * is always true, so the rule fires on every single command.** Omitting the key
 * from a `.strict()` object makes that a parse error rather than a lint finding.
 *
 * `scope` is BANNED for the same class of reason and is absent from the rule
 * envelope below: `agent_in` compares literally against an agent id that is
 * always a UUID, never the string `"claude-code"`, so a scoped rule matches
 * nothing, forever, silently.
 *
 * ── The third ban needs an actual check ──────────────────────────────────────
 *
 * A command matcher (`detail_contains` / `detail_matches`) and a file matcher
 * (`file_glob`) in ONE condition can never both be satisfied: the guard's mapper
 * is an if/else chain, so no real tool call ever carries both a command and a
 * file path. This schema refuses the combination.
 */
export const MatchConditionSchema = z
  .object({
    kind: z.string().min(1),
    label: z.string().min(1).optional(),
    detail_contains: z.array(z.string().min(1)).min(1).optional(),
    detail_matches: z
      .array(DetailMatchPatternSchema)
      .min(1)
      .max(DETAIL_MATCHES_MAX_PATTERNS)
      .optional(),
    file_glob: z.string().min(1).optional(),
  })
  .strict()
  .superRefine((condition, ctx) => {
    const hasCommandMatcher =
      condition.detail_contains !== undefined || condition.detail_matches !== undefined;
    if (hasCommandMatcher && condition.file_glob !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "a condition may not combine a command matcher (detail_contains / detail_matches) with a file matcher (file_glob): no real tool call carries both, so the condition can never match. Split it into two conditions under any_of.",
      });
    }
  });

/**
 * Match composition — conditions combined with `any_of` (OR), `all_of` (AND)
 * and/or `none_of` (negation).
 *
 * At least one of `any_of` or `all_of` must be present. `none_of` is an optional
 * refinement that CANNOT stand alone: a match must positively select calls
 * before excluding some. A pure-negation match is satisfied by every
 * non-matching call and, at `block`, would deny everything the agent does.
 */
export const MatchSchema = z
  .object({
    any_of: z.array(MatchConditionSchema).min(1).optional(),
    all_of: z.array(MatchConditionSchema).min(1).optional(),
    none_of: z.array(MatchConditionSchema).min(1).optional(),
  })
  .strict()
  .refine((data) => data.any_of !== undefined || data.all_of !== undefined, {
    message: "At least one of 'any_of' or 'all_of' must be provided",
  });

// ── Fixtures ────────────────────────────────────────────────────────────────

/**
 * The tools a fixture may name. Free-form on purpose — the guard's matcher grows
 * (`mcp__*` alone is unbounded) and a closed enum here would reject a valid rule
 * for a tool this package has not heard of yet.
 */
const FixtureToolSchema = z.string().min(1);

/**
 * A fixture on the COMMAND channel: `Bash`, `PowerShell`, `WebSearch` (its
 * query is ordinary text), and `mcp__*` (its serialized input).
 */
const CommandFixtureSchema = z
  .object({ tool: FixtureToolSchema, command: z.string().min(1) })
  .strict();

/** A fixture on the FILE channel: `Edit`, `Write`, `Read`, `NotebookEdit`. */
const FileFixtureSchema = z
  .object({ tool: FixtureToolSchema, file_path: z.string().min(1) })
  .strict();

/**
 * One fixture: a tool call this rule must match, or must not.
 *
 * A bare string is shorthand for `{ tool: "Bash", command: "<string>" }`, which
 * covers most rules and keeps them terse. Anything else is an object with a
 * `tool` plus **exactly one** of `command` or `file_path` — the two channels.
 * `.strict()` on each variant is what makes "exactly one" true: a
 * `command` object carrying a `file_path` matches neither variant.
 *
 * The parse output is always normalized to the object form, so the harness has
 * exactly one shape to feed the evaluator.
 *
 * ── There is no `url` channel ─────────────────────────────────────────────────
 *
 * **The evaluator cannot see a URL**: the only two attribute keys any matcher
 * reads are `detail` and `file_path`, and there is no `url` field in the condition
 * schema. A value written to `url` would be read by nothing, so a `WebFetch` rule
 * would match nothing, silently — the same failure `scope` is banned for. There
 * are no website rules and `WebFetch` is not intercepted; `WebSearch` is, because
 * its query is text on the command channel.
 *
 * A `url` key therefore fails to parse rather than becoming a fixture that tests
 * nothing. `__tests__/schema.test.ts` pins that.
 */
export const FixtureSchema = z.union([
  z
    .string()
    .min(1)
    .transform((command) => ({ tool: "Bash" as const, command })),
  CommandFixtureSchema,
  FileFixtureSchema,
]);

/**
 * The two directions every rule must prove, through the real evaluator.
 *
 * **`block` means "this rule MUST match"; `allow` means "this rule MUST NOT
 * match".** They are not verdicts. Five of the eight packs default to `ask` or
 * `warn`, and `warn` folds into an allow verdict, so reading `block` as "the
 * guard denies" would fail every `warn` rule and make the negative fixture
 * vacuous for them.
 *
 * Both are `.min(1)`: CI only has to fail on a rule missing a
 * negative fixture, but requiring it here moves that failure to authoring time,
 * where it costs a keystroke instead of a pull-request round trip.
 */
export const FixturesSchema = z
  .object({
    block: z.array(FixtureSchema).min(1),
    allow: z.array(FixtureSchema).min(1),
  })
  .strict();

// ── The rule ────────────────────────────────────────────────────────────────

/**
 * One published rule.
 *
 * `.strict()` rejects any key not declared here, so an unknown field fails to parse
 * rather than riding along into the published package.
 *
 * `description` carries the rule's COVERAGE LIMITS, verbatim — e.g. that an
 * `rm -rf` rule misses `rm -fr`. It is a convention rather than a schema
 * constraint, because no validator can tell a real limit from a sentence shaped
 * like one.
 */
export const RuleSchema = z
  .object({
    /** Stable: a rule id is never renamed. */
    id: z.string().min(1),
    /** The pack this rule belongs to. Validated against `PACKS` by the registry. */
    category: z.string().min(1),
    severity: SeveritySchema,
    defaultAction: ActionSchema,
    title: z.string().min(1),
    description: z.string().min(1),
    match: MatchSchema,
    fixtures: FixturesSchema,
  })
  .strict();

// ── Types ───────────────────────────────────────────────────────────────────

/** How dangerous the caught action is. Never a price. */
export type Severity = (typeof SEVERITIES)[number];

/** What the guard does on a match. */
export type Action = (typeof ACTIONS)[number];

/** One condition matched against a tool call. */
export type MatchCondition = z.infer<typeof MatchConditionSchema>;

/** A composed match — `any_of` / `all_of` / `none_of`. */
export type Match = z.infer<typeof MatchSchema>;

/** A fixture as authored: a bare command string, or a tagged single-channel object. */
export type FixtureInput = z.input<typeof FixtureSchema>;

/** A fixture after parsing — always the tagged object form. */
export type Fixture = z.output<typeof FixtureSchema>;

/** The must-match / must-not-match pair every rule ships. */
export type Fixtures = z.infer<typeof FixturesSchema>;

/** One published rule, as authored. */
export type RuleInput = z.input<typeof RuleSchema>;

/** One published rule, parsed and normalized. */
export type Rule = z.output<typeof RuleSchema>;

// ── Parsing ─────────────────────────────────────────────────────────────────

/**
 * Validate a rule from unknown input.
 *
 * It answers "is this a well-formed rule?" — it does NOT answer "does this rule
 * actually fire on the command you think it does." That needs the evaluator, which
 * is not part of this package.
 *
 * @param input - Unknown input, e.g. parsed JSON or a rule module's default export.
 * @returns A Zod SafeParseReturnType — check `.success` before reading `.data`.
 */
export function parseRule(input: unknown): z.SafeParseReturnType<unknown, Rule> {
  return RuleSchema.safeParse(input);
}

/**
 * Parse a rule, or throw with the reason.
 *
 * Used by rule modules themselves via {@link defineRule}, so an authoring
 * mistake fails at import — which is to say, at test time — rather than
 * surviving into a corpus that only validates what it remembers to check.
 */
export function parseRuleOrThrow(input: unknown): Rule {
  const result = parseRule(input);
  if (!result.success) {
    const id =
      typeof input === "object" && input !== null && "id" in input
        ? String((input as { id: unknown }).id)
        : "<unknown id>";
    throw new Error(`invalid guardrails rule ${id}: ${result.error.message}`);
  }
  return result.data;
}

/**
 * Declare a rule. Validates at module load, so a malformed rule cannot reach the
 * registry — the corpus is only as trustworthy as its weakest unvalidated entry.
 */
export function defineRule(rule: RuleInput): Rule {
  return parseRuleOrThrow(rule);
}
