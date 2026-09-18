import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `git checkout` used as a discard rather than as a branch switch.
 *
 * The two spellings are different commands sharing a name: `git checkout main`
 * moves HEAD and is the single most common git command there is, while
 * `git checkout -- .` overwrites the working tree from the index. Only the second
 * shape is matched, and the `allow` fixtures are the first shape, because a rule
 * that fires on every branch switch is uninstalled within the hour.
 */
export const wtCheckoutDiscard: Rule = {
  id: "wt.checkout-discard",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "git checkout used to discard working-tree changes",
  description:
    'Overwrites files in the working tree from the index or from another commit, discarding uncommitted edits. Matches the discard spellings only — `git checkout -- <path>`, a bare `git checkout .`, and the `-f`/`--force` forms. It deliberately does NOT match an ordinary branch switch (`git checkout main`, `git checkout -b feature/x`), which is the same command doing something else entirely. It also MISSES `git checkout <commit> <path>` written without the `--` separator. Global flags between `git` and `checkout` are tolerated (`git -C <dir> checkout -- .`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bgit${LEADING_FLAGS}\\s+checkout\\s+--\\s`,
          `\\bgit${LEADING_FLAGS}\\s+checkout\\s+\\.(\\s|$)`,
          `\\bgit${LEADING_FLAGS}\\s+checkout\\s+-f\\b`,
          `\\bgit${LEADING_FLAGS}\\s+checkout\\s+--force\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git checkout -- src/api.ts"),
      bash("git checkout -- ."),
      bash("git checkout ."),
      bash("git checkout -f"),
      bash("git -C /repo checkout -- src/api.ts"),
      bash("git --no-pager checkout -f"),
    ],
    allow: [
      ...mentions("git checkout -- src/api.ts"),
      bash("git checkout main"),
      bash("git checkout -b feature/new-thing"),
      bash("git checkout tags/v1.2.3"),
      bash("git checkout --track origin/release"),
    ],
  },
};
