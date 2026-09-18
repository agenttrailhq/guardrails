// cspell:words modelcontextprotocol
import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, file, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The agent command as its own word: at the start, or after whitespace, `;`, `&`, `|`, `(` or `/`. */
const AT_COMMAND = "(?:^|[\\s;&|(/])";

/** Arguments that stay outside any quoted run, so a quoted prompt is never read as a subcommand. */
const ARGS = "\\s(?:[^|;&\"']*\\s)?";

/**
 * Adding an MCP server to an agent from the command line.
 *
 * An MCP server is a new set of tools the agent can call, often a program fetched and started on
 * the spot. Registering one through the agent's own CLI widens its reach without a file edit; the
 * file route (`.mcp.json`) is held by `fs.agent-self-config`.
 */
export const acMcpServerAdd: Rule = {
  id: "ac.mcp-server-add",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "Adding an MCP server to an agent",
  description:
    "Holds the commands that register an MCP server with a coding agent — `claude mcp add`, `claude mcp add-json`, `claude mcp add-from-claude-desktop`, `codex mcp add` and `gemini mcp add` — and `claude --mcp-config`, which attaches servers to a single session. Each gives an agent a new set of tools, often a program fetched and started on the spot, with nobody reviewing the change. Deliberately NOT matched: listing or removing servers (`claude mcp list`, `claude mcp remove`), and the MCP Inspector (`npx @modelcontextprotocol/inspector`), which is a debugging tool rather than a registration. Cursor has no command for this, so its `.cursor/mcp.json`, in a project or the home directory, is matched as a file instead; a project's `.mcp.json` is held by `fs.agent-self-config`. Misses servers written into `~/.claude.json` or Gemini's `settings.json` with a file tool, and a global flag whose value is quoted when it sits before `mcp`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone, as long as every shell metacharacter stays inside the quotes.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${AT_COMMAND}claude(?:-code)?${ARGS}mcp\\s+add(?:-json|-from-claude-desktop)?\\b`,
          `${AT_COMMAND}(?:codex|gemini)${ARGS}mcp\\s+add\\b`,
          `${AT_COMMAND}claude(?:-code)?${ARGS}--mcp-config\\b`,
        ],
      },
      // Cursor has no `mcp add` command; its servers are added by editing this file.
      { kind: "execute_tool", file_glob: "**/.cursor/mcp.json" },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("claude mcp add --transport http docs https://docs.example.com/mcp"),
      bash("claude mcp add github -- npx -y @modelcontextprotocol/server-github"),
      bash(`claude mcp add-json weather '{"type":"stdio","command":"weather-mcp"}'`),
      bash("codex mcp add docs -- npx -y docs-mcp-server"),
      bash("gemini mcp add filesystem npx -y @modelcontextprotocol/server-filesystem ."),
      bash('claude --mcp-config ./servers.json -p "summarize the open issues"'),
      bash("npx @anthropic-ai/claude-code mcp add docs https://docs.example.com/mcp"),
      pwsh("claude mcp add --transport http docs https://docs.example.com/mcp"),
      file(".cursor/mcp.json", "Write"),
      file("/Users/dev/.cursor/mcp.json"),
    ],
    allow: [
      ...mentions("claude mcp add --transport http docs https://docs.example.com/mcp"),
      bash("claude mcp list"),
      bash("claude mcp remove github"),
      bash("claude mcp get github"),
      bash("codex mcp list"),
      bash("gemini mcp list"),
      bash("npx @modelcontextprotocol/inspector"),
      file("config/mcp.json"),
      file(".cursor/rules/style.mdc"),
      bash("pnpm run test"),
    ],
  },
};
