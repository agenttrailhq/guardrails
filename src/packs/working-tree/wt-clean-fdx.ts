import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `git clean -fd` deletes untracked files, and `-x` adds the ignored ones — which
 * on a real checkout means `.env`, local certificates, and every scratch file the
 * developer has not committed yet. Nothing about it is recoverable from git.
 *
 * The `allow` fixtures are the dry runs, because that is the neighboring command:
 * `git clean -nd` is what a careful person types first.
 */
export const wtCleanFdx: Rule = {
  id: "wt.clean-fdx",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "git clean -fd deletes untracked files",
  description:
    'Deletes untracked files and directories, and with `-x` the git-ignored ones too — which on a working checkout means local `.env` files, certificates and scratch work that exist nowhere else. Git holds no copy of any of it. The dry-run forms (`git clean -nd`, `--dry-run`) are deliberately NOT matched, since that is what a careful person runs first. Known miss: `git clean` driven from a wrapper script whose own text does not name it. Global flags between `git` and `clean` are tolerated on both the block and the dry-run exemption (`git -C <dir> clean -fd`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bgit${LEADING_FLAGS}\\s+clean\\b[^|;&]*-[a-z]*f[a-z]*d`,
          `\\bgit${LEADING_FLAGS}\\s+clean\\b[^|;&]*-[a-z]*d[a-z]*f`,
          `\\bgit${LEADING_FLAGS}\\s+clean\\b[^|;&]*--force\\b`,
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [`\\bgit${LEADING_FLAGS}\\s+clean\\b[^|;&]*--dry-run\\b`],
      },
    ],
  },
  fixtures: {
    block: [
      bash("git clean -fd"),
      bash("git clean -fdx"),
      bash("git clean -xdf"),
      bash("git clean --force -d"),
      bash("git -C /repo clean -fd"),
      bash("git --no-pager clean -fdx"),
    ],
    allow: [
      ...mentions("git clean -fd"),
      bash("git clean -nd"),
      bash("git -C /repo clean -fd --dry-run"),
      bash("git clean --dry-run -d"),
      bash("git clean -n"),
      bash("git status --short"),
    ],
  },
};
