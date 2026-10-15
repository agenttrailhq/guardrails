/**
 * The two OWASP lists a rule's `owasp` field may cite, as plain data.
 *
 * No zod here, so the corpus entry (`./rules.ts`) can re-export it and stay validator-free.
 * `schema.ts` validates a rule's `owasp` field against `OWASP_IDS`.
 *
 * - OWASP Top 10 for Agentic Applications (v1.0, the 2026 edition): ASI01 to ASI10.
 * - OWASP Top 10 for LLM Applications 2026 (v1.0): LLM01 to LLM10.
 *
 * An id names the risk a rule addresses at the point where it becomes a command or a file
 * change. It is never a claim that the rule covers the whole risk.
 */

/** Every id a rule may cite, in list order: the agentic list first, then the LLM list. */
export const OWASP_IDS = [
  "ASI01",
  "ASI02",
  "ASI03",
  "ASI04",
  "ASI05",
  "ASI06",
  "ASI07",
  "ASI08",
  "ASI09",
  "ASI10",
  "LLM01",
  "LLM02",
  "LLM03",
  "LLM04",
  "LLM05",
  "LLM06",
  "LLM07",
  "LLM08",
  "LLM09",
  "LLM10",
] as const;

/** One OWASP risk id, e.g. `ASI02` or `LLM06`. */
export type OwaspId = (typeof OWASP_IDS)[number];

/** One risk on an OWASP list. */
export interface OwaspRisk {
  readonly id: OwaspId;
  readonly title: string;
}

/** OWASP Top 10 for Agentic Applications, v1.0. */
export const OWASP_AGENTIC: readonly OwaspRisk[] = [
  { id: "ASI01", title: "Agent Goal Hijack" },
  { id: "ASI02", title: "Tool Misuse and Exploitation" },
  { id: "ASI03", title: "Identity and Privilege Abuse" },
  { id: "ASI04", title: "Agentic Supply Chain Vulnerabilities" },
  { id: "ASI05", title: "Unexpected Code Execution" },
  { id: "ASI06", title: "Memory and Context Poisoning" },
  { id: "ASI07", title: "Insecure Inter-Agent Communication" },
  { id: "ASI08", title: "Cascading Failures" },
  { id: "ASI09", title: "Human-Agent Trust Exploitation" },
  { id: "ASI10", title: "Rogue Agents" },
];

/** OWASP Top 10 for LLM Applications 2026, v1.0. */
export const OWASP_LLM: readonly OwaspRisk[] = [
  { id: "LLM01", title: "Prompt Injection" },
  { id: "LLM02", title: "Sensitive Information Disclosure" },
  { id: "LLM03", title: "Excessive Agency" },
  { id: "LLM04", title: "Supply Chain" },
  { id: "LLM05", title: "Data and Model Poisoning" },
  { id: "LLM06", title: "Unbounded Consumption" },
  { id: "LLM07", title: "Misinformation" },
  { id: "LLM08", title: "Hidden Context Exposure" },
  { id: "LLM09", title: "Vector and Embedding Weaknesses" },
  { id: "LLM10", title: "Improper Output Handling" },
];

/** Where each list is published. */
export const OWASP_SOURCES = {
  agentic: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
  llm: "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
} as const;

/** True when `value` is one of `OWASP_IDS`, spelled exactly (upper-case, no suffix). */
export function isOwaspId(value: unknown): value is OwaspId {
  return typeof value === "string" && (OWASP_IDS as readonly string[]).includes(value);
}

/** The id's position in `OWASP_IDS`, or -1. The order a rule must list its ids in. */
export function owaspIndex(id: string): number {
  return (OWASP_IDS as readonly string[]).indexOf(id);
}

/** The risk's title, e.g. `owaspTitle("ASI02")` is "Tool Misuse and Exploitation". */
export function owaspTitle(id: OwaspId): string {
  const risk = [...OWASP_AGENTIC, ...OWASP_LLM].find((r) => r.id === id);
  // Unreachable for a typed `OwaspId`: the two lists hold every id, which a test pins.
  return risk?.title ?? id;
}
