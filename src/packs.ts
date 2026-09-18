// cspell:words exfiltration
/**
 * The eleven packs, and the order they are presented in.
 *
 * These ids are authoritative and shared with the rules authored against them,
 * and with the guard's `config.json` `disabledPacks`. Renaming one of these is a
 * breaking change to a user's config file.
 *
 * Working-tree destruction leads: destructive git commands are the most frequently
 * documented coding-agent failure, with public incident reports across Claude
 * Code, Gemini CLI and Codex.
 *
 * Per-pack rule counts are deliberately NOT encoded here: a rule count asserted in
 * code becomes a reason to write a weak rule to hit a number.
 */
export const PACKS = [
  "working-tree",
  "destructive-data",
  "prod-infra",
  "secret-exposure",
  "rce-supply-chain",
  "safety-bypass",
  "privilege-supply-chain",
  "file-scope",
  "agent-context",
  "test-integrity",
  "exfiltration",
] as const;

/** One of the eleven pack ids. A rule's `category` is always one of these. */
export type Pack = (typeof PACKS)[number];

/** Is this string one of the eleven pack ids? */
export function isPack(value: string): value is Pack {
  return (PACKS as readonly string[]).includes(value);
}
