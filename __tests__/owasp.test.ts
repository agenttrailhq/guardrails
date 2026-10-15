/**
 * The OWASP id lists and the `owasp` field that cites them.
 *
 * A rule's ids are read by people deciding what a rule is for, so a wrong spelling must fail to
 * parse, and the failure has to say what to write instead.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import {
  getRule,
  isOwaspId,
  OWASP_AGENTIC,
  OWASP_IDS,
  OWASP_LLM,
  type OwaspId,
  owaspIndex,
  owaspTitle,
  parseRule,
  type Rule,
  type RuleInput,
  RuleSchema,
} from "../src/index.js";

const base = getRule("wt.reset-hard") as Rule;

/** Parse `base` with a different `owasp` value; `undefined` removes the field. */
function withOwasp(owasp: unknown) {
  const { owasp: _drop, ...rest } = base;
  return parseRule(owasp === undefined ? rest : { ...rest, owasp });
}

/** The issues of a failed parse, as `[path, message]` pairs. */
function issues(owasp: unknown): [string, string][] {
  const result = withOwasp(owasp);
  if (result.success) throw new Error(`expected ${JSON.stringify(owasp)} to fail`);
  return result.error.issues.map((i) => [i.path.join("."), i.message]);
}

describe("the two OWASP lists", () => {
  it("holds ten agentic and ten LLM risks, in order", () => {
    expect(OWASP_AGENTIC.map((r) => r.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `ASI${String(i + 1).padStart(2, "0")}`),
    );
    expect(OWASP_LLM.map((r) => r.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}`),
    );
  });

  it("OWASP_IDS is the two lists, agentic first", () => {
    expect([...OWASP_IDS]).toEqual([...OWASP_AGENTIC, ...OWASP_LLM].map((r) => r.id));
  });

  it("gives every id a title", () => {
    for (const id of OWASP_IDS) expect(owaspTitle(id), id).not.toBe(id);
    expect(owaspTitle("ASI02")).toBe("Tool Misuse and Exploitation");
    expect(owaspTitle("LLM06")).toBe("Unbounded Consumption");
  });

  it("recognizes only exact ids", () => {
    expect(isOwaspId("ASI02")).toBe(true);
    for (const v of ["asi02", "ASI11", "LLM00", "LLM06:2026", "", 2, null]) {
      expect(isOwaspId(v), String(v)).toBe(false);
    }
    expect(owaspIndex("ASI01")).toBe(0);
    expect(owaspIndex("LLM10")).toBe(19);
    expect(owaspIndex("nope")).toBe(-1);
  });
});

describe("the owasp field's TypeScript type", () => {
  it("is OwaspId[] on both the authored and the parsed rule", () => {
    expectTypeOf<RuleInput["owasp"]>().toEqualTypeOf<OwaspId[] | undefined>();
    expectTypeOf<Rule["owasp"]>().toEqualTypeOf<OwaspId[] | undefined>();
    // Checked by `tsc`: each line below must NOT compile. If the type widened again, the
    // directive itself would become the error.
    // @ts-expect-error -- not an OWASP id
    const typo: RuleInput["owasp"] = ["ASI2"];
    // @ts-expect-error -- not a string
    const number: RuleInput["owasp"] = [42];
    expect([typo, number]).toHaveLength(2);
  });
});

describe("the owasp field", () => {
  it("is optional: a rule without it parses", () => {
    const result = withOwasp(undefined);
    expect(result.success).toBe(true);
    expect(result.success && "owasp" in result.data).toBe(false);
  });

  it("accepts a valid list in order", () => {
    const result = withOwasp(["ASI02", "ASI10", "LLM03"]);
    expect(result.success && result.data.owasp).toEqual(["ASI02", "ASI10", "LLM03"]);
  });

  it("is declared on the rule schema", () => {
    expect(Object.keys(RuleSchema.shape)).toContain("owasp");
  });

  it("rejects an id on neither list, at its index", () => {
    expect(issues(["ASI02", "ASI11"])).toEqual([
      [
        "owasp.1",
        "owasp: `ASI11` is not an OWASP id. Use an id from the OWASP Top 10 for Agentic Applications (ASI01 to ASI10) or for LLM Applications 2026 (LLM01 to LLM10)",
      ],
    ]);
    expect(issues(["LLM00"])[0]?.[0]).toBe("owasp.0");
    expect(issues([2])[0]?.[1]).toMatch(/^owasp: 2 is not an OWASP id/);
  });

  it("names the exact spelling for a lower-case or suffixed real id", () => {
    expect(issues(["asi02"])).toEqual([
      [
        "owasp.0",
        "owasp: `asi02` is not an OWASP id. Use the upper-case id without a suffix: `ASI02`",
      ],
    ]);
    expect(issues(["ASI02", "LLM06:2026"])).toEqual([
      [
        "owasp.1",
        "owasp: `LLM06:2026` is not an OWASP id. Use the upper-case id without a suffix: `LLM06`",
      ],
    ]);
  });

  it("rejects a duplicate, at the second occurrence", () => {
    expect(issues(["ASI02", "ASI02"])).toEqual([["owasp.1", "owasp: `ASI02` is listed twice"]]);
  });

  it("rejects a list out of order", () => {
    const message = "owasp: out of order; list ASI ids before LLM ids, each ascending";
    expect(issues(["LLM03", "ASI02"])).toEqual([["owasp", message]]);
    expect(issues(["ASI10", "ASI02"])).toEqual([["owasp", message]]);
  });

  it("rejects an empty list", () => {
    expect(issues([])).toEqual([
      ["owasp", "owasp: omit the field rather than giving an empty list"],
    ]);
  });

  it("rejects a value that is not a list", () => {
    expect(issues("ASI02")[0]?.[0]).toBe("owasp");
  });
});
