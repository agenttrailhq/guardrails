/**
 * The MCP command-field tables, checked against the corpus that relies on them.
 *
 * `MCP_COMMAND_FIELDS` and `MCP_GENERIC_COMMAND_FIELDS` decide which arguments of an MCP call a
 * `command` condition reads. A block fixture on an MCP tool is only proof for a command guardrail
 * if its command sits in one of those fields; a fixture whose trigger sits in a field the tables do
 * not name would match the whole serialized input and nothing narrower. These tests make that
 * structural property explicit, and pin which guardrails read the `content` channel.
 */
import { describe, expect, it } from "vitest";
import {
  type Fixture,
  type MatchCondition,
  MCP_COMMAND_FIELDS,
  MCP_GENERIC_COMMAND_FIELDS,
  mcp,
  RULES,
  type Rule,
} from "../src/index.js";

/** The tool segment of `mcp__<server>__<tool>`, or `undefined` for a tool that is not MCP. */
function toolSegment(tool: string): string | undefined {
  const parts = tool.split("__");
  if (parts[0] !== "mcp" || parts.length < 3) return undefined;
  return parts.slice(2).join("__");
}

/**
 * The text a `command` condition reads on an MCP fixture, per the two tables: the mapped fields
 * for a mapped tool, else the generic ones, each a top-level non-empty string, joined with a
 * newline. `undefined` when none is present.
 */
function commandText(fixture: Fixture): string | undefined {
  if (!("command" in fixture)) return undefined;
  const segment = toolSegment(fixture.tool);
  if (segment === undefined) return undefined;
  const input = JSON.parse(fixture.command) as Record<string, unknown>;
  const fields = MCP_COMMAND_FIELDS[segment] ?? MCP_GENERIC_COMMAND_FIELDS;
  const values = fields
    .map((field) => input[field])
    .filter((value): value is string => typeof value === "string" && value.length > 0);
  return values.length > 0 ? values.join("\n") : undefined;
}

function positives(rule: Rule): MatchCondition[] {
  return [...(rule.match.any_of ?? []), ...(rule.match.all_of ?? [])];
}

function isMcpFixture(fixture: Fixture): boolean {
  return "command" in fixture && toolSegment(fixture.tool) !== undefined;
}

describe("MCP_COMMAND_FIELDS", () => {
  it("is keyed by bare tool segments, each naming at least one field once", () => {
    for (const [tool, fields] of Object.entries(MCP_COMMAND_FIELDS)) {
      expect(tool, tool).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(tool.startsWith("mcp__"), tool).toBe(false);
      expect(fields.length, tool).toBeGreaterThan(0);
      expect(new Set(fields).size, tool).toBe(fields.length);
      for (const field of fields) expect(field, `${tool}.${field}`).toMatch(/^[A-Za-z0-9_]+$/);
    }
  });

  it("has a block fixture for every mapped tool", () => {
    const covered = new Set(
      RULES.flatMap((rule) => rule.fixtures.block)
        .filter(isMcpFixture)
        .map((fixture) => toolSegment(fixture.tool)),
    );
    const missing = Object.keys(MCP_COMMAND_FIELDS).filter((tool) => !covered.has(tool));
    expect(missing).toEqual([]);
  });
});

describe("MCP_GENERIC_COMMAND_FIELDS", () => {
  it("is the four generic names", () => {
    expect([...MCP_GENERIC_COMMAND_FIELDS]).toEqual(["command", "cmd", "sql", "script"]);
  });
});

describe("MCP block fixtures on command guardrails", () => {
  it("carry their command in a field the tables read", () => {
    const offenders: string[] = [];
    for (const rule of RULES) {
      const readsCommand = positives(rule).some(
        (c) =>
          (c.detail_contains !== undefined || c.detail_matches !== undefined) &&
          c.channel !== "content",
      );
      if (!readsCommand) continue;
      for (const fixture of rule.fixtures.block.filter(isMcpFixture)) {
        if (commandText(fixture) === undefined) {
          offenders.push(
            `${rule.id}: ${fixture.tool} ${"command" in fixture ? fixture.command : ""}`,
          );
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the check BITES: a trigger in a field that does not execute has no command text", () => {
    expect(commandText(mcp({ title: "fix the rm -rf / bug" }))).toBeUndefined();
    expect(commandText(mcp({ sql: "DROP TABLE users;" }, "mcp__postgres__query"))).toBe(
      "DROP TABLE users;",
    );
    // A mapped tool never falls back to the generic names.
    expect(commandText(mcp({ command: "rm -rf /" }, "mcp__sqlite__write_query"))).toBeUndefined();
  });
});

describe("the content channel", () => {
  it("is carried only by block-hardcoded-secrets, on every positive condition", () => {
    const tagged = RULES.filter((rule) =>
      [...positives(rule), ...(rule.match.none_of ?? [])].some((c) => c.channel !== undefined),
    ).map((rule) => rule.id);
    expect(tagged).toEqual(["block-hardcoded-secrets"]);
    const secrets = RULES.find((rule) => rule.id === "block-hardcoded-secrets")!;
    expect(positives(secrets).every((c) => c.channel === "content")).toBe(true);
  });

  it("block-hardcoded-secrets proves a key in MCP prose with no command field", () => {
    const secrets = RULES.find((rule) => rule.id === "block-hardcoded-secrets")!;
    const prose = secrets.fixtures.block.filter(
      (fixture) => isMcpFixture(fixture) && commandText(fixture) === undefined,
    );
    expect(prose.length).toBeGreaterThan(0);
  });
});
