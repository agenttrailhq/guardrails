import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Merging past branch protection, or removing the protection itself. This is the
 * rule that protects the review process rather than the code — and the review
 * process is the only reason any of the other rules get looked at.
 */
export const gbAdminMerge: Rule = {
  id: "gb.admin-merge",
  category: "safety-bypass",
  severity: "high",
  defaultAction: "require_approval",
  title: "Merging past branch protection, or deleting it",
  description:
    'Holds `gh pr merge --admin` (which merges without the required reviews or checks), a `gh api` call that deletes or replaces a branch-protection rule, and `gh ruleset delete`. Does NOT match an ordinary merge (`gh pr merge --squash`) or a READ of the protection settings, which is how you find out what is configured. It only sees the GitHub CLI: the same change made in the web UI, or through another client, is invisible to it. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bgh\\s+pr\\s+merge\\b[^|;&]*--admin\\b",
          "\\bgh\\s+api\\b[^|;&]*(-X\\s*|--method\\s+)(delete|put)\\b[^|;&]*protection\\b",
          "\\bgh\\s+api\\b[^|;&]*protection\\b[^|;&]*(-X\\s*|--method\\s+)(delete|put)\\b",
          "\\bgh\\s+ruleset\\s+delete\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("gh pr merge 42 --admin --squash"),
      bash("gh api -X DELETE repos/o/r/branches/main/protection"),
      bash("gh ruleset delete 7"),
    ],
    allow: [
      ...mentions("gh pr merge 42 --admin --squash"),
      bash("gh pr merge 42 --squash"),
      bash("gh api repos/o/r/branches/main/protection"),
      bash("gh pr list --limit 20"),
      bash("gh ruleset list"),
    ],
  },
};
