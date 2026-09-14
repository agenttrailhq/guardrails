/**
 * The corpus itself — rules only, and **deliberately free of zod**.
 *
 * ── Why this is a separate entry point from `index.ts` ───────────────────────
 *
 * The guard bundles this catalog into its hook script, the file Claude Code
 * executes before EVERY tool call, in a fresh Node process, under a 10s ceiling.
 * That bundle must not carry a validator it never calls.
 *
 * The package ROOT cannot satisfy that: `index.ts` re-exports `./schema.js`, which
 * value-imports zod. So the guard imports `@agenttrail/guardrails/guardrails` — this
 * file — whose whole import graph is `./packs.js`, `./exemptions.js` and
 * `./fixtures.js` (all three plain data) plus a TYPE-only
 * reference to `./schema.js`, which esbuild erases. Everyone else keeps using the
 * root and gets the schema with it.
 *
 * A cold import of the package root, validating every rule through `defineRule`,
 * takes about twice as long as an empty Node process. The subpath avoids that on
 * every tool call.
 *
 * ── Where validation runs ───────────────────────────────────────────────────
 *
 * At test time: `__tests__/corpus.test.ts` runs `parseRule()` over every rule and
 * fails on any invalid one, and proves that sweep bites with a deliberately
 * malformed rule. `defineRule` is exported for contributors authoring locally.
 *
 * So every rule file exports a plain object literal typed `satisfies Rule` with a
 * TYPE-only schema import. `corpus.test.ts` is what stops one from drifting.
 */

import { rules as destructiveData } from "./packs/destructive-data/index.js";
import { rules as fileScope } from "./packs/file-scope/index.js";
import { rules as privilegeSupplyChain } from "./packs/privilege-supply-chain/index.js";
import { rules as prodInfra } from "./packs/prod-infra/index.js";
import { rules as rceSupplyChain } from "./packs/rce-supply-chain/index.js";
import { rules as safetyBypass } from "./packs/safety-bypass/index.js";
import { rules as secretExposure } from "./packs/secret-exposure/index.js";
import { rules as workingTree } from "./packs/working-tree/index.js";
import { PACKS, type Pack } from "./packs.js";
import type { Rule } from "./schema.js";

export * from "./exemptions.js";
export * from "./fixtures.js";
export * from "./packs.js";
/**
 * The rule TYPES, re-exported so a consumer of this subpath does not have to
 * reach for the package root (and its validator) just to name a `Rule`.
 *
 * `export type` is fully erased at build time — `dist/guardrails.js` carries no zod,
 * which `guard/src/__tests__/built-artifact.test.ts` asserts against the bytes.
 */
export type {
  Action,
  Fixture,
  FixtureInput,
  Fixtures,
  Match,
  MatchCondition,
  Rule,
  RuleInput,
  Severity,
} from "./schema.js";
/**
 * The corpus stamp — its version and publication date.
 *
 * It belongs on THIS entry rather than only on the root because it describes the
 * corpus, and because `stamp.ts` is two string constants with no imports: a
 * consumer that must stay zod-free can ask how old its rules are without reaching
 * for the validator. The root re-exports it too, via `export * from "./rules.js"`.
 */
export * from "./stamp.js";

/**
 * Every pack's rules, keyed by pack id.
 *
 * `Record<Pack, …>` is doing real work: adding a pack to `PACKS` without wiring
 * its rules here is a compile error, not a pack that silently ships empty.
 */
export const RULES_BY_PACK: Record<Pack, readonly Rule[]> = {
  "working-tree": workingTree,
  "destructive-data": destructiveData,
  "prod-infra": prodInfra,
  "secret-exposure": secretExposure,
  "rce-supply-chain": rceSupplyChain,
  "safety-bypass": safetyBypass,
  "privilege-supply-chain": privilegeSupplyChain,
  "file-scope": fileScope,
};

/**
 * The whole catalog, in pack order.
 *
 * Built from `PACKS` rather than by concatenating the imports, so the order is
 * the declared one and a pack cannot be omitted by a missed line.
 */
export const RULES: readonly Rule[] = PACKS.flatMap((pack) => RULES_BY_PACK[pack]);

/** Look up one rule by id. `undefined` when nothing matches. */
export function getRule(id: string): Rule | undefined {
  return RULES.find((rule) => rule.id === id);
}

/** Every rule in one pack, in authored order. */
export function rulesForPack(pack: Pack): readonly Rule[] {
  return RULES_BY_PACK[pack];
}
