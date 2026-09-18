import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The agent command as its own word: at the start, or after whitespace, `;`, `&`, `|`, `(` or `/`. */
const AT_COMMAND = "(?:^|[\\s;&|(/])";

/** Arguments that stay outside any quoted run, so a flag inside a quoted prompt is not read as one. */
const ARGS = "\\s(?:[^|;&\"']*\\s)?";

/**
 * An agent starting another agent to run a task without a human in the loop.
 *
 * Each spawned agent reads, writes and runs commands of its own, and can spawn more. No rule can
 * put a number on that — conditions on counts and durations are not available before a tool call
 * runs — so this holds the shape instead: a coding agent invoked non-interactively from a shell.
 */
export const acRecursiveAgentInvoke: Rule = {
  id: "ac.recursive-agent-invoke",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "An agent starting another agent non-interactively",
  description:
    "Holds a coding agent started from a shell to run a task on its own: `claude -p` or `--print` (including through `npx @anthropic-ai/claude-code`), `codex exec` or `codex e`, `gemini -p` or `--prompt`, `cursor-agent -p` or `--print`, and `aider` run non-interactively with `--message`, `--msg`, `-m`, or `-f` — the short form of `--message-file`, which disables chat mode. `--message-file` needs no arm of its own: the `--message` arm is a prefix of it and catches it. Every spawned agent reads, writes and runs commands of its own and can start more, which is how spend and reach multiply without anyone watching. This catches the shape, not the cost: no rule can count calls or tokens before a tool runs. Deliberately NOT matched: `codex -p`, which selects a profile rather than a prompt, `--version` and `--help`, and listing commands such as `claude mcp list`. Misses Cursor's CLI when it is invoked by its primary name `agent`, which is too generic to match on, Gemini run headless by piping into it without `-p`, and a flag placed after a quoted argument. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone, as long as every shell metacharacter stays inside the quotes.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${AT_COMMAND}claude(?:-code)?${ARGS}(?:-p|--print)\\b`,
          `${AT_COMMAND}codex${ARGS}(?:exec|e)\\b`,
          `${AT_COMMAND}gemini${ARGS}(?:-p|--prompt)\\b`,
          `${AT_COMMAND}cursor-agent${ARGS}(?:-p|--print)\\b`,
          `${AT_COMMAND}aider${ARGS}(?:--message|--msg|-m|-f)\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash('claude -p "summarize the failing tests"'),
      bash('npx @anthropic-ai/claude-code --print "fix the lint errors"'),
      bash('claude --model sonnet -p "write the changelog"'),
      bash('codex exec "add unit tests for the parser"'),
      bash('codex e "add unit tests for the parser"'),
      bash('gemini -p "explain this repository"'),
      bash('cursor-agent -p "refactor the auth module"'),
      bash('aider --message "rename foo to bar" src/app.py'),
      bash('aider -m "rename foo to bar" src/app.py'),
      bash("aider --message-file task.md src/app.py"),
      bash("aider -f task.md src/app.py"),
      pwsh('claude -p "summarize the failing tests"'),
    ],
    allow: [
      ...mentions("claude -p summarize the failing tests"),
      bash("claude --version"),
      bash("claude mcp list"),
      bash("codex --help"),
      bash("codex -p work"),
      bash("codex login"),
      bash("gemini --version"),
      bash("cursor-agent --help"),
      bash("aider --help"),
      bash("aider --model sonnet src/app.py"),
      bash("pnpm run build"),
      bash("git log -p src/app.ts"),
    ],
  },
};
