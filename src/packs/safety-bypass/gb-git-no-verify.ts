// cspell:words Dskip

import {
  HTTP_BODY_MENTION,
  LEADING_FLAGS,
  PRINT_MENTION,
  SEARCH_MENTION,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mcp, mentionInEcho, mentionInPost, mentionInSearch } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `--no-verify` skips the hooks the team installed on purpose: the formatter, the
 * type check, the secret scanner. It is the single most common way a check that
 * everyone believes is running turns out not to be.
 *
 * `mvn -DskipTests package` is a REQUIRED negative here: it is exactly the command
 * a rule about "skipping checks" drifts into matching if nobody pins it.
 */
export const gbGitNoVerify: Rule = {
  id: "gb.git-no-verify",
  category: "safety-bypass",
  severity: "medium",
  defaultAction: "require_approval",
  title: "git --no-verify skips the hooks the team installed",
  description:
    'Commits, pushes or merges with `--no-verify`, which skips the pre-commit and pre-push hooks a team installed on purpose — the formatter, the type check, the secret scanner. It is the most common way a check everyone believes is running turns out not to be. Deliberately does NOT widen to skipping tests in general: `mvn -DskipTests package` is ordinary work and is asserted as a negative. Known over-match: a `-n` anywhere in a `git commit` line, including inside a message. Global flags between `git` and its subcommand are tolerated (`git -C <dir> commit --no-verify`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt. `git commit` is NOT one of those carriers here, because this rule\'s own trigger is a flag of `git commit`: a commit message that quotes `--no-verify` still asks.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bgit${LEADING_FLAGS}\\s+(commit|push|merge)\\b[^|;&]*--no-verify\\b`,
          `\\bgit${LEADING_FLAGS}\\s+commit\\b[^|;&]*\\s-n\\b`,
        ],
      },
    ],
    none_of: [SEARCH_MENTION, PRINT_MENTION, HTTP_BODY_MENTION],
  },
  fixtures: {
    block: [
      bash('git commit --no-verify -m "wip"'),
      bash("git push --no-verify origin main"),
      bash('git commit -n -m "wip"'),
      bash('git -C /repo commit --no-verify -m "wip"'),
      bash("git --no-pager push --no-verify origin main"),
      mcp({ command: 'git commit --no-verify -m "wip"' }),
    ],
    allow: [
      mentionInSearch("git commit --no-verify -m wip"),
      mentionInEcho("git commit --no-verify -m wip"),
      mentionInPost("git commit --no-verify -m wip"),
      bash('git commit -m "add the thing"'),
      bash("git push origin main"),
      bash("mvn -DskipTests package"),
      bash("git commit --amend --no-edit"),
    ],
  },
};
