import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The two resets that throw away work without saying `--hard`.
 *
 * `--merge` discards changes to files that differ between HEAD and the target;
 * `--keep` aborts if they are modified, but discards otherwise. Both read as
 * cautious, which is exactly why they are worth a prompt.
 */
export const wtResetMerge: Rule = {
  id: "wt.reset-merge",
  category: "working-tree",
  severity: "medium",
  defaultAction: "require_approval",
  title: "git reset --merge / --keep can discard local changes",
  description:
    'Resets with `--merge` or `--keep`, both of which can silently drop uncommitted changes to files that differ between HEAD and the target commit. They read as the cautious options, which is why they are worth a prompt rather than a block. Does NOT match `git reset --soft` or a bare `git reset`, neither of which touches the working tree, and it does not cover `git merge --abort`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: ["\\bgit\\s+reset\\s+--merge\\b", "\\bgit\\s+reset\\s+--keep\\b"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git reset --merge"),
      bash("git reset --keep origin/main"),
      bash("git reset --merge HEAD~1"),
    ],
    allow: [
      ...mentions("git reset --merge"),
      bash("git reset --soft HEAD~1"),
      bash("git reset HEAD~1"),
      bash("git merge --abort"),
      bash("git reset"),
    ],
  },
};
