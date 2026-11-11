import { LEADING_FLAGS, QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The id has no dotted pack prefix. Guardrail ids are stable identifiers, so it is not
 * renamed to match the others.
 */
export const blockForcePush: Rule = {
  id: "block-force-push",
  category: "working-tree",
  severity: "high",
  defaultAction: "block",
  owasp: ["ASI02", "LLM03"],
  title: "Block git force-push",
  description:
    "Overwrites a remote branch's history, destroying commits other people may already have pulled. The command must contain `git push` and the force flag must sit in the same pipeline segment, so searching for the phrase is not blocked. A global flag between `git` and `push` is tolerated (`git -C <dir> push --force`, `git --no-pager push …`), and an absolute tool path such as `/usr/bin/git` still matches. Also blocks a refspec that starts with a plus sign (`git push origin +main`, git's own force syntax), `f` inside a short-flag cluster (`-uf`), and `--mirror`, which overwrites and deletes remote refs. A plus sign inside a branch name, or anywhere but the start of an argument, is not matched. The safer `--force-with-lease` form IS still blocked; exempting it needs a negative lookahead this corpus does not use. MISSES an alias such as `git pf`; a force configured rather than typed (a plus refspec in the remote's push configuration, or a mirror remote); a ref update through the hosting provider's API; a force-push issued by a wrapper script whose own text does not say `git push`; and deleting a remote branch (`git push origin :main`, `git push --delete`), which this guardrail does not claim. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        detail_matches: [
          // One pattern, so each `git push` in a long command is scanned once, not once per
          // form. The forms: `--force`, `f` in a short-flag cluster, a positional argument
          // that starts with a plus sign (a forced refspec), and `--mirror`.
          `\\bgit${LEADING_FLAGS}\\s+push\\b[^|;&]*(?:--force|\\s-[a-z]{0,8}f[a-z]{0,8}\\b|\\s["']?\\+[^\\s"']|--mirror\\b)`,
        ],
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
      bash("git -C /repo push --force origin main"),
      bash("git --no-pager push --force"),
      bash("/usr/bin/git push -f origin main"),
      bash("git push origin +main"),
      bash("git push origin +HEAD:main"),
      bash("git push origin +refs/heads/main:refs/heads/main"),
      bash("git push -uf origin main"),
      bash("git push --mirror origin"),
      bash('git push origin "+main"'),
      bash("git -C /repo push origin +main"),
      bash("/usr/bin/git push origin +main"),
      bash('bash -c "git push origin +main"'),
      bash("sudo git push origin +main"),
    ],
    allow: [
      ...mentions("git push origin main --force"),
      ...mentions("git push origin +main"),
      bash("git push origin main"),
      bash("git push --tags"),
      bash("grep -rn 'push -f' ."),
      bash("git push --set-upstream origin feature/x"),
      bash("git push origin feature+x"),
      bash("git push origin main:feature+x"),
      bash("git push -u origin main"),
      bash("git push --follow-tags"),
    ],
  },
};
