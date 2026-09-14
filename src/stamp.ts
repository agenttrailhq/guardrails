/**
 * The catalog's own version and publication date.
 *
 * These are the two facts the offline guard needs in order to tell someone how old
 * their protection is. The guard has no update check and no network path for rules,
 * so a user's rules are frozen on the day they installed and nothing else can tell
 * them that.
 *
 * ── Why the stamp lives HERE and not in `@agenttrail/guard` ──────────────────
 * The guard BUNDLES this package at build time, so it is *this* package's version
 * that determines which rules a user is actually running. The guard's own version
 * answers a different question and would be the wrong number: `guard@0.4.1` may ship
 * an unchanged catalog, and two different guard versions may carry the same rules.
 *
 * ── This module imports nothing, and that is load-bearing ───────────────────
 * It is exported from `rules.ts`, the zod-free entry the guard bundles into the
 * file Claude Code runs before every tool call. Two string constants add nothing to
 * that bundle; an import of `schema.ts` here would add zod to it. Add no imports here.
 *
 * ── Both constants are hand-written, and that is deliberate ──────────────────
 * A build-time `define` would reach `dist/` only, so the value would exist in the
 * published tarball and be absent from the source every test imports — the shipped
 * value would be the one value never exercised. `__tests__/stamp.test.ts` pins
 * `CATALOG_VERSION` to `package.json` so the two cannot drift in silence.
 *
 * ── AT RELEASE, BUMP BOTH CONSTANTS BELOW, TOGETHER ──────────────────────────
 * Bumping `package.json`'s version alone turns `stamp.test.ts` red, and that is the
 * point: it is what brings whoever cut the release into this file, where the date is
 * a few lines away. Publish order is `guardrails` first, then `guard`;
 * a guard release carries whatever stamp was here when it was built.
 *
 * Forgetting to advance the date understates how fresh the rules are, which tells a
 * user to update when they need not. Forgetting in the other direction would tell a
 * user they are current when they are stale. The first is the safe failure and the
 * one this arrangement produces.
 */

/**
 * The corpus version.
 *
 * Pinned to `package.json`'s `version` by `__tests__/stamp.test.ts` — this is a copy
 * of that value, not an independent one, and the test is what makes the copy safe.
 */
export const CATALOG_VERSION = "0.0.1";

/**
 * When the rules in this catalog reached their current state, as an ISO-8601
 * instant. The question it answers is not "when did this reach a registry" but "how
 * old are the rules I am running".
 *
 * If a release cannot source a real date, leave it absent rather than approximate:
 * the guard handles a missing date, and a wrong date that looks right is worse than
 * a missing one.
 */
export const CATALOG_PUBLISHED_AT = "2026-09-07T12:44:09Z";
