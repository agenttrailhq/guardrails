import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The id has no dotted pack prefix. Rule ids are stable identifiers, so it is not
 * renamed to match the others.
 */
export const blockForcePush: Rule = {
  id: "block-force-push",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  title: "Block git force-push",
  description:
    'Overwrites a remote branch\'s history, destroying commits other people may already have pulled. The command must contain the literal `git push` and the flag must sit in the same pipeline segment, so searching for the phrase is not blocked. The safer `--force-with-lease` form IS still blocked; exempting it needs a negative lookahead this corpus does not use. MISSES an alias such as `git pf`, and a force-push issued by a wrapper script whose own text does not say `git push`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        detail_matches: ["\\bgit\\s+push\\b[^|;&]*--force", "\\bgit\\s+push\\b[^|;&]*\\s-f\\b"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git push origin main --force"),
      bash("git push --force origin main"),
      bash("git push -f origin feature/x"),
      bash("git push origin main --force-with-lease"),
    ],
    allow: [
      ...mentions("git push origin main --force"),
      bash("git push origin main"),
      bash("git push --tags"),
      bash("grep -rn 'push -f' ."),
      bash("git push --set-upstream origin feature/x"),
    ],
  },
};
