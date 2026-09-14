/**
 * `@agenttrail/guardrails` — the rule corpus, its schema, and its fixtures.
 *
 * Rules only: no evaluator, and no dependency besides zod (see `schema.ts`).
 * `agenttrail-guard` bundles this catalog and evaluates it locally.
 *
 * 56 rules across eight packs, each shipping at least one `block` fixture (must
 * match) and one `allow` fixture (must not match).
 *
 * ── Two entry points, and the difference matters ─────────────────────────────
 *
 * This root re-exports BOTH the corpus and the schema, so it carries zod.
 * `@agenttrail/guardrails/guardrails` (`./rules.ts`) carries the corpus alone and is
 * zod-free — that is the entry the guard bundles into the file Claude Code
 * runs before every tool call. Read `rules.ts`'s header before changing either.
 */

export * from "./rules.js";
export * from "./schema.js";
