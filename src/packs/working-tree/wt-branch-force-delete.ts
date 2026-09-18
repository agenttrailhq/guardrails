// cspell:words Dskip

import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The one rule in this pack that MUST use `detail_contains`, because case is the
 * entire signal: `-D` force-deletes an unmerged branch and `-d` refuses to. Under
 * `detail_matches` — which the engine compiles case-INSENSITIVELY — the two are
 * indistinguishable, and the rule would fire on the safe spelling a developer
 * types after every merge.
 *
 * `detail_contains` is AND-within-a-condition, so `["git branch", "-D"]` requires
 * both, which is what keeps `mvn -DskipTests package` out.
 */
export const wtBranchForceDelete: Rule = {
  id: "wt.branch-force-delete",
  category: "working-tree",
  severity: "medium",
  defaultAction: "require_approval",
  title: "git branch -D force-deletes an unmerged branch",
  description:
    'Deletes a branch even when its commits are not merged anywhere, so the work becomes unreachable. This rule is CASE-SENSITIVE on purpose and that is why it uses detail_contains: `-D` force-deletes while `-d` refuses to delete unmerged work, and the engine\'s regex matcher is case-insensitive, so a regex here would fire on the safe spelling every time a developer cleans up after a merge. Known miss: the flags written separately as `--delete --force` in the reverse order, and any alias. The `git branch` anchor tolerates repeated or tab whitespace and a global flag in between (`git  branch -D …`, `git -C <dir> branch -D …`), and an absolute tool path such as `/usr/bin/git` still matches, while `-D` stays a case-sensitive substring so the safe `-d` is not caught. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+branch\\b`],
        detail_contains: ["-D"],
      },
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+branch\\b`],
        detail_contains: ["--delete", "--force"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git branch -D feature/abandoned"),
      bash("git branch --delete --force feature/abandoned"),
      bash("git branch -D feature/a feature/b"),
      bash("git  branch -D feature/double-space"),
      bash("git -C /repo branch -D feature/abandoned"),
      bash("git --no-pager branch --delete --force feature/abandoned"),
    ],
    allow: [
      ...mentions("git branch -D feature/abandoned"),
      bash("git branch -d merged-feature"),
      bash("git branch -a"),
      bash("git branch --show-current"),
      bash("mvn -DskipTests package"),
    ],
  },
};
