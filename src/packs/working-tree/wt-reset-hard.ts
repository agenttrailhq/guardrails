import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
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
    'Discards every uncommitted change in the working tree, irrecoverably — there is no reflog for work that was never committed. Does NOT match `git restore` (see wt.restore-path), `git checkout -- .` (see wt.checkout-discard), or a reset spelled `--hard=...`; and it cannot tell a scratch clone from your only copy of the work, so a deliberate reset in a throwaway checkout is blocked too. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: ["\\bgit\\s+reset\\s+--hard\\b"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git reset --hard"),
      bash("git reset --hard HEAD~3"),
      bash("git reset --hard origin/main"),
      pwsh("git reset --hard"),
    ],
    allow: [
      ...mentions("git reset --hard"),
      bash("git reset --soft HEAD~1"),
      bash("git reset src/api.ts"),
      bash("git reset --mixed HEAD"),
      bash("git reset HEAD~1"),
    ],
  },
};
