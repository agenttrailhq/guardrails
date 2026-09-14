// cspell:words undrop

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * A dropped stash is gone: `git stash drop` deletes the commit the stash pointed
 * at and there is no `git stash undrop`. `require_approval` rather than `block`
 * because clearing an old stash is a normal thing to do on purpose.
 */
export const wtStashDrop: Rule = {
  id: "wt.stash-drop",
  category: "working-tree",
  severity: "medium",
  defaultAction: "require_approval",
  title: "git stash drop / clear deletes stashed work",
  description:
    'Deletes stashed work, which has no undo — the stash commit becomes unreachable and there is no `git stash undrop`. Held for approval rather than blocked, because clearing an old stash is a normal deliberate act. Does NOT match `git stash pop` (which applies and then drops, and whose failure mode is a conflict rather than a loss) or `git stash push`. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: ["\\bgit\\s+stash\\s+(drop|clear)\\b"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [bash("git stash drop"), bash("git stash clear"), bash("git stash drop stash@{2}")],
    allow: [
      ...mentions("git stash drop"),
      bash("git stash push -m wip"),
      bash("git stash list"),
      bash("git stash pop"),
      bash("git stash show -p"),
    ],
  },
};
