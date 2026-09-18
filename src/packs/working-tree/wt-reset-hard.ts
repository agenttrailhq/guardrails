import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The pack's lead rule, and the guard's canonical example.
 *
 * `label` is `{Bash,PowerShell}` and not `Bash`: on Windows without Git Bash,
 * Claude Code does not register a `Bash` tool at all, so a Bash-only arm is inert
 * on an entire platform.
 *
 * A one-element brace (`{Bash}`) is NOT the same thing and must never be written:
 * it matches nothing in some positions, silently. A single tool is a bare label.
 */
export const wtResetHard: Rule = {
  id: "wt.reset-hard",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "git reset --hard discards uncommitted work",
  description:
    'Discards every uncommitted change in the working tree, irrecoverably — there is no reflog for work that was never committed. Does NOT match `git restore` (see wt.restore-path), `git checkout -- .` (see wt.checkout-discard), or a reset spelled `--hard=...`; and it cannot tell a scratch clone from your only copy of the work, so a deliberate reset in a throwaway checkout is blocked too. A global flag between `git` and `reset` is tolerated (`git -C <dir> reset --hard`, `git --no-pager …`, `git -c k=v …`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+reset\\s+--hard\\b`],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git reset --hard"),
      bash("git reset --hard HEAD~3"),
      bash("git reset --hard origin/main"),
      bash("git -C /tmp/scratch reset --hard"),
      bash("git --no-pager reset --hard HEAD~2"),
      bash("git -c core.pager=cat reset --hard"),
      bash("/usr/bin/git reset --hard"),
      pwsh("git reset --hard"),
      mcp({ command: "git reset --hard HEAD~2" }),
    ],
    allow: [
      ...mentions("git reset --hard"),
      bash("git reset --soft HEAD~1"),
      bash("git reset src/api.ts"),
      bash("git reset --mixed HEAD"),
      bash("git reset HEAD~1"),
      mcp({ command: "git status" }),
    ],
  },
};
