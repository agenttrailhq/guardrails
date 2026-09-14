import { QUOTED_MENTION } from "../../exemptions.js";
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
    'Deletes untracked files and directories, and with `-x` the git-ignored ones too — which on a working checkout means local `.env` files, certificates and scratch work that exist nowhere else. Git holds no copy of any of it. The dry-run forms (`git clean -nd`, `--dry-run`) are deliberately NOT matched, since that is what a careful person runs first. Known miss: `git clean` driven from a wrapper script whose own text does not name it. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bgit\\s+clean\\b[^|;&]*-[a-z]*f[a-z]*d",
          "\\bgit\\s+clean\\b[^|;&]*-[a-z]*d[a-z]*f",
          "\\bgit\\s+clean\\b[^|;&]*--force\\b",
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: ["\\bgit\\s+clean\\b[^|;&]*--dry-run\\b"],
      },
    ],
  },
  fixtures: {
    block: [
      bash("git clean -fd"),
      bash("git clean -fdx"),
      bash("git clean -xdf"),
      bash("git clean --force -d"),
    ],
    allow: [
      ...mentions("git clean -fd"),
      bash("git clean -nd"),
      bash("git clean --dry-run -d"),
      bash("git clean -n"),
      bash("git status --short"),
    ],
  },
};
