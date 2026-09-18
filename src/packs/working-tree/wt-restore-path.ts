import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `git restore` is the modern spelling of the discard half of `git checkout`, and
 * it is the one a coding agent reaches for, because it is what the porcelain
 * suggests. The `--staged` form only unstages — the file on disk is untouched —
 * so it is excluded rather than matched, which is why this rule has a `none_of`.
 *
 * The exclusion has a stated hole: `git restore --staged --worktree <path>` does
 * discard, and is exempted here. Closing it needs a negative lookahead, and the
 * over-match it would buy back (every routine `git restore --staged`) is worse
 * than the miss.
 */
export const wtRestorePath: Rule = {
  id: "wt.restore-path",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "git restore discards uncommitted changes to a path",
  description:
    'Overwrites files in the working tree from the index, discarding uncommitted edits to them. `git restore --staged` is deliberately NOT matched: it only unstages, and the file on disk is untouched. The cost of that exclusion is a known miss — `git restore --staged --worktree <path>` DOES discard and is exempted here, because expressing the distinction needs a negative lookahead this corpus does not use. Global flags between `git` and `restore` are tolerated on both the block and the `--staged` exemption (`git -C <dir> restore .`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+restore\\b`],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+restore\\s+--staged\\b`],
      },
    ],
  },
  fixtures: {
    block: [
      bash("git restore src/api.ts"),
      bash("git restore ."),
      bash("git restore --source=HEAD~2 src/api.ts"),
      bash("git -C /repo restore src/api.ts"),
      bash("git --no-pager restore ."),
    ],
    allow: [
      ...mentions("git restore src/api.ts"),
      bash("git restore --staged src/api.ts"),
      bash("git -C /repo restore --staged src/api.ts"),
      bash("git stash push -m wip src/api.ts"),
      bash("git status --short"),
    ],
  },
};
