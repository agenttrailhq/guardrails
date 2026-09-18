// cspell:words hookspath repointing

import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Turning the hooks off at the source rather than per-command. `core.hooksPath`
 * pointed somewhere empty disables every hook in the repository permanently, and
 * nothing about the next commit looks any different.
 */
export const gbHooksDisable: Rule = {
  id: "gb.hooks-disable",
  category: "safety-bypass",
  severity: "medium",
  defaultAction: "require_approval",
  title: "Disabling git hooks at the source",
  description:
    'Holds a command that turns git hooks off permanently rather than for one commit — repointing `core.hooksPath`, setting HUSKY=0 or HUSKY_SKIP_HOOKS, or deleting/unsetting the executable bit on files in `.git/hooks/`. A READ of the setting (`git config core.hooksPath` with no value) is not matched. Nothing about the next commit looks any different afterwards, which is what makes it worth a prompt. Does NOT match other `git config` writes (`user.email`, `core.pager`) or installing hooks (`husky install`). It MISSES a hooksPath set through an environment variable in a shell profile. A global flag between `git` and `config` is tolerated (`git -C <dir> config …`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bgit${LEADING_FLAGS}\\s+config\\b[^|;&]*core\\.hookspath\\s+\\S`,
          "\\bhusky\\s*=\\s*0\\b",
          "\\bhusky_skip_hooks\\s*=\\s*1\\b",
          "\\brm\\b[^|;&]*\\.git/hooks/",
          "\\bchmod\\s+-x\\b[^|;&]*\\.git/hooks/",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("git config core.hooksPath /dev/null"),
      bash("git -C /repo config core.hooksPath /dev/null"),
      bash('HUSKY=0 git commit -m "wip"'),
      bash("rm -f .git/hooks/pre-commit"),
    ],
    allow: [
      ...mentions("git config core.hooksPath /dev/null"),
      bash("git config user.email dev@example.com"),
      bash("git config --list"),
      bash("pnpm husky install"),
      bash("git config core.hooksPath"),
    ],
  },
};
