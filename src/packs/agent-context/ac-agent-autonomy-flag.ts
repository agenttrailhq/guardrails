import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The agent command as its own word: at the start, or after whitespace, `;`, `&`, `|`, `(` or `/`. */
const AT_COMMAND = "(?:^|[\\s;&|(/])";

/** Arguments that stay outside any quoted run, so a flag inside a quoted prompt is not read as one. */
const ARGS = "\\s(?:[^|;&\"']*\\s)?";

/**
 * Switching off an agent's approval step or sandbox.
 *
 * Every flag here is the one its tool documents as "run without asking". An agent that sets it on
 * another agent — or on its own next session — removes the human check that everything else in
 * this library relies on.
 */
export const acAgentAutonomyFlag: Rule = {
  id: "ac.agent-autonomy-flag",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "Switching off an agent's approvals or sandbox",
  description:
    "Holds the flags that make a coding agent act without asking: Claude Code's `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions` and `--permission-mode bypassPermissions`; Codex's `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `--full-auto`, `-a never` or `--ask-for-approval never`, `--sandbox danger-full-access`, and the same two settings passed as `approval_policy` or `sandbox_mode` config values; Gemini's `--yolo`, `-y` and `--approval-mode yolo`; `cursor-agent --force`, `-f` or `--yolo`; and Aider's `--yes-always`, its accepted short form `--yes`, and `AIDER_YES_ALWAYS`. Deliberately NOT matched: the narrower modes (`--permission-mode plan` or `acceptEdits`, `--sandbox workspace-write`, `-a on-request`, `--approval-mode auto_edit`), and `--auto-approve` or `-y` on any other command — `terraform apply --auto-approve` and `apt-get install -y` are not agents. Misses Cursor's CLI under its primary name `agent`, which is too generic to match on, and a setting written to an agent's config file with a file tool, which `fs.agent-self-config` holds for Claude Code and Codex. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone, as long as every shell metacharacter stays inside the quotes.",
  match: {
    any_of: [
      // Claude Code and Codex.
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\s--(?:allow-)?dangerously-skip-permissions\\b",
          "\\s--permission-mode(?:\\s+|=)bypassPermissions\\b",
          "\\s--dangerously-bypass-approvals-and-sandbox\\b",
          `${AT_COMMAND}codex${ARGS}(?:--yolo|--full-auto)\\b`,
          `${AT_COMMAND}codex${ARGS}(?:-a|--ask-for-approval)(?:\\s+|=)never\\b`,
          "\\s(?:--sandbox|-s)(?:\\s+|=)danger-full-access\\b",
          "\\bapproval_policy\\s*=\\s*[\"']?never\\b",
          "\\bsandbox_mode\\s*=\\s*[\"']?danger-full-access\\b",
        ],
      },
      // Gemini, Cursor's agent and Aider.
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${AT_COMMAND}(?:gemini|cursor-agent)${ARGS}--yolo\\b`,
          `${AT_COMMAND}gemini${ARGS}-y\\b`,
          "\\s--approval-mode(?:\\s+|=)yolo\\b",
          `${AT_COMMAND}cursor-agent${ARGS}(?:-f|--force)\\b`,
          `${AT_COMMAND}aider${ARGS}--yes\\b`,
          "\\bAIDER_YES(?:_ALWAYS)?\\s*=",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("claude --dangerously-skip-permissions"),
      bash('claude -p "fix the build" --permission-mode bypassPermissions'),
      bash('codex exec --dangerously-bypass-approvals-and-sandbox "migrate the schema"'),
      bash("codex --yolo"),
      bash("codex --full-auto"),
      bash("codex -a never"),
      bash('codex exec --sandbox danger-full-access "run the migrations"'),
      bash('codex exec -c approval_policy=never "run the migrations"'),
      bash('gemini --yolo -p "clean up the repo"'),
      bash("gemini --approval-mode=yolo"),
      bash('cursor-agent -p --force "update the dependencies"'),
      bash('aider --yes-always --message "apply the refactor"'),
      bash("export AIDER_YES_ALWAYS=true"),
      pwsh("claude --dangerously-skip-permissions"),
    ],
    allow: [
      ...mentions("claude --dangerously-skip-permissions"),
      bash("claude --permission-mode plan"),
      bash("claude --permission-mode acceptEdits"),
      bash("codex --sandbox workspace-write"),
      bash("codex -a on-request"),
      bash("gemini --approval-mode auto_edit"),
      bash("terraform apply --auto-approve"),
      bash("apt-get install -y curl"),
      bash("aider --no-auto-commits src/app.py"),
      bash("cursor-agent --help"),
      bash("git push --force-with-lease origin feature/x"),
      bash("pnpm run lint"),
    ],
  },
};
