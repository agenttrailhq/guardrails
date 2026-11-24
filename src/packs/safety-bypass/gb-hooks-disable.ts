// cspell:words hookspath repointing

import {
  GIT_PRE,
  HOOKSPATH,
  LEADING_FLAGS,
  QUOTED_MENTION,
  SEP,
  SHELL_AND_MCP,
} from "../../exemptions.js";
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
  owasp: ["ASI09"],
  title: "Disabling git hooks at the source",
  description:
    "Holds a command that turns git hooks off permanently rather than for one commit — repointing `core.hooksPath`, setting HUSKY=0 or HUSKY_SKIP_HOOKS, or deleting/unsetting the executable bit on files in `.git/hooks/`. A READ of the setting (`git config core.hooksPath` with no value) is not matched. Nothing about the next commit looks any different afterwards, which is what makes it worth a prompt. Does NOT match other `git config` writes (`user.email`, `core.pager`) or installing hooks (`husky install`). Also held: unsetting it (`git config --unset core.hooksPath`, `--unset-all`, `unset`, `--remove-section core`), which brings back `.git/hooks` and so turns husky and any other hooks folder off, and the key written with up to eight quotes or backslashes before or between its letters (`core.hooks''Path`). It MISSES more than eight such characters, a hooksPath set through an environment variable in a shell profile, a key with a variable inside it (`core.hooks$X…`), and config read from another file (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG`, `include.path`). A global flag between `git` and `config` is tolerated (`git -C <dir> config …`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
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
          // Removing the setting brings back .git/hooks, which turns husky and any other
          // hooks folder off.
          `${GIT_PRE}${SEP}config\\b[^|;&\\n]{0,200}(?:--unset(?:-all)?|${SEP}unset)${SEP}{1,4}${HOOKSPATH}`,
          `${GIT_PRE}${SEP}config\\b[^|;&\\n]{0,200}--re(?:move|name)-section${SEP}{1,4}["']?core["']?(?:${SEP}|$)`,
          // A write of the key with quotes or backslashes inside it.
          `${GIT_PRE}${SEP}config\\b[^|;&\\n]{0,200}${SEP}${HOOKSPATH}${SEP}{1,4}["']?\\S`,
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
      // Removing the setting brings back .git/hooks, which turns husky's folder off.
      bash("git config --unset core.hooksPath"),
      bash("git config --unset-all core.hooksPath"),
      bash("git config unset core.hooksPath"),
      bash("git config --remove-section core"),
      // Quotes or backslashes inside the key.
      bash("git config core.hooks''Path /dev/null"),
      bash("git config --unset core.hooks''Path"),
      bash("git config core.hooks''''Path /x"),
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
