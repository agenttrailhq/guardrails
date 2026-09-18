import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The id has no dotted pack prefix. Rule ids are stable identifiers, so it is not
 * renamed to match the others.
 */
export const requireApprovalRmRf: Rule = {
  id: "require-approval-rm-rf",
  category: "working-tree",
  severity: "high",
  defaultAction: "require_approval",
  title: "Hold `rm -rf` for approval",
  description:
    'Recursive-force delete: held for approval rather than blocked, which is the honest strength for an operation that is destructive but often legitimate. Catches -rf, -Rf, -rvf and the reversed -fr spelling in any case, `rm --recursive`, and PowerShell\'s `Remove-Item -Recurse`. Clearing a build directory is EXEMPT (node_modules, dist, build, out, coverage, target, .next, .turbo, .cache, .vite, .parcel-cache): that shape appears about 220 times in real Claude Code traces against about 3 for a dangerous delete, and a rule that asks every time is a rule people switch off. An absolute path, a $VARIABLE, a ~ path or a source directory still asks. Does NOT match a delete via a file tool, or flags split across arguments such as `rm -r -f x`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\brm\\s+-[a-z]*r[a-z]*f",
          "\\brm\\s+-[a-z]*f[a-z]*r",
          "\\brm\\s+--recursive\\b",
          "\\bremove-item\\b[^|;&]*-recurse",
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\brm\\s+-\\S+\\s+(\\./)?(node_modules|dist|build|out|coverage|target|\\.next|\\.turbo|\\.cache|\\.vite|\\.parcel-cache)(/|\\b)",
        ],
      },
    ],
  },
  fixtures: {
    block: [
      bash("rm -Rf /home/user/projects"),
      bash("rm -fr src/generated"),
      bash("rm -rf $HOME/Projects/old-client"),
      pwsh("Remove-Item -Recurse -Force C:/projects/old"),
    ],
    allow: [
      ...mentions("rm -Rf /home/user/projects"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf node_modules"),
      bash("rm -rf build/"),
      bash("rm -rf dist"),
      bash("./confirm -rf x"),
      bash("rm package-lock.json"),
    ],
  },
};
