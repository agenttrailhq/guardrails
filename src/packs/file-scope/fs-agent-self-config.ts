import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The agent editing its own permissions.
 *
 * This is the pack's sharpest case: a hook config, an MCP server list or a
 * settings file is where "what is this agent allowed to do" is written down, and
 * an agent that can edit it can widen its own reach without anyone reviewing the
 * change. It includes the guard's OWN config, deliberately.
 */
export const fsAgentSelfConfig: Rule = {
  id: "fs.agent-self-config",
  category: "file-scope",
  severity: "high",
  defaultAction: "require_approval",
  title: "The agent editing its own configuration",
  description:
    "Holds a file tool opening the files that define what the agent itself is allowed to do — Claude Code settings and hooks, an MCP server list, a plugin manifest, Cursor rules, a Codex config, and the guard's own config.json and guardrails.json. An agent that can edit these can widen its own reach with nobody reviewing the change. Does NOT match ordinary project files, or `.claude/commands/*.md`, which are prompts rather than permissions. Bounded to WELL-KNOWN paths: no working directory or project root reaches the guard, so it can only match names it already knows.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.claude/settings*.json" },
      { kind: "execute_tool", file_glob: "**/.claude/hooks/**" },
      { kind: "execute_tool", file_glob: "**/.claude-plugin/**" },
      { kind: "execute_tool", file_glob: "**/.mcp.json" },
      { kind: "execute_tool", file_glob: "**/.cursor/rules/**" },
      { kind: "execute_tool", file_glob: "**/.codex/config.toml" },
      { kind: "execute_tool", file_glob: "**/.agenttrail/guard/config.json" },
      { kind: "execute_tool", file_glob: "**/.agenttrail/guard/guardrails.json" },
    ],
  },
  fixtures: {
    block: [
      file(".claude/settings.json"),
      file(".claude/settings.local.json"),
      file("/home/dev/.agenttrail/guard/config.json", "Write"),
      file(".mcp.json"),
    ],
    allow: [
      file(".claude/commands/deploy.md"),
      file("src/index.ts"),
      file("package.json"),
      file("README.md"),
    ],
  },
};
