// cspell:words Dskip veri verif aeiopqsvz HOOKSPATH

import {
  GIT_PRE,
  HOOKSPATH,
  HTTP_BODY_MENTION,
  IN_WORD,
  LEADING_FLAGS,
  PRINT_MENTION,
  SEARCH_MENTION,
  SEP,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mcp, mentionInEcho, mentionInPost, mentionInSearch, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `--no-verify` skips the hooks the team installed on purpose: the formatter, the
 * type check, the secret scanner. It is the single most common way a check that
 * everyone believes is running turns out not to be.
 *
 * `mvn -DskipTests package` is a REQUIRED negative here: it is exactly the command
 * a guardrail about "skipping checks" drifts into matching if nobody pins it.
 */
export const gbGitNoVerify: Rule = {
  id: "gb.git-no-verify",
  category: "safety-bypass",
  severity: "medium",
  defaultAction: "require_approval",
  owasp: ["ASI09"],
  title: "git --no-verify skips the hooks the team installed",
  description:
    "Commits, pushes or merges with `--no-verify`, which skips the pre-commit and pre-push hooks a team installed on purpose — the formatter, the type check, the secret scanner. It is the most common way a check everyone believes is running turns out not to be. Deliberately does NOT widen to skipping tests in general: `mvn -DskipTests package` is ordinary work and is asserted as a negative. Also held: the prefixes git accepts (`--no-veri`, `--no-verif`), quotes or escapes the shell removes from the flag (`--no-\"verify\"`, `$'\\x2d\\x2dno-verify'`), `n` inside a short cluster (`-nm`, `-anm`, `-sn`), and a hooks folder chosen for one command: `git -c core.hooksPath=…`, `--config-env`, `GIT_CONFIG_KEY_n` or `GIT_CONFIG_PARAMETERS`, including up to eight quotes or backslashes inside the key (`core.hooks''Path`). Known misses: a key with a variable inside it (`core.hooks$X…`), and config read from another file (`GIT_CONFIG_GLOBAL=…`, `GIT_CONFIG=…`, `-c include.path=…`). Known over-match: a `-n` anywhere in a `git commit` line, including inside a message; `-Sn`, which signs with key `n`; any `-c core.hooksPath` value, including a real folder; and a blank inside the key (`core.hooks Path`). More than eight removable characters before or between the key's letters are not read. Global flags between `git` and its subcommand are tolerated (`git -C <dir> commit --no-verify`, `--no-pager`, `-c k=v`), and an absolute tool path such as `/usr/bin/git` still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt. `git commit` is NOT one of those carriers here, because the trigger here is a flag of `git commit`: a commit message that quotes `--no-verify` still asks.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bgit${LEADING_FLAGS}\\s+(commit|push|merge)\\b[^|;&]*--no-verify\\b`,
          `\\bgit${LEADING_FLAGS}\\s+commit\\b[^|;&]*\\s-n\\b`,
          // --no-verify and its working prefixes --no-veri and --no-verif, with quotes or escapes
          // between the letters (--no-"verify", --no-ver\\ify).
          `${GIT_PRE}${SEP}${IN_WORD}-${IN_WORD}-${IN_WORD}n${IN_WORD}o${IN_WORD}-${IN_WORD}v${IN_WORD}e${IN_WORD}r${IN_WORD}i(?:${IN_WORD}f(?:${IN_WORD}y)?)?${IN_WORD}(?:${SEP}|=|$)`,
          // n inside a short cluster, as a whole argument outside any quoted message (-nm, -anm,
          // -sn, "-n", $'-n'); an option that takes a value (-m, -F, -c, -C, -t) before it ends it.
          `${GIT_PRE}${SEP}commit\\b(?:${SEP}{1,4}(?:"[^"\\n]{0,300}"|'[^'\\n]{0,300}'|[^\\s"'|;&]{1,200})){0,16}${SEP}{1,4}\\$?["'\\\\]{0,4}-[aeiopqsvz"'\\\\]{0,12}n[a-z"']{0,8}(?:${SEP}|$)`,
          // A hooks folder chosen for one command: -c or --config-env, across continuations.
          `${GIT_PRE}(?:${SEP}|\\\\\\n){1,6}(?:-c(?:${SEP}|\\\\\\n){1,6}|--config-env(?:[=\\s]|\\\\\\n){1,6})${HOOKSPATH}`,
          // The same through git's environment, including PowerShell's $env:GIT_CONFIG_KEY_0 = '…'.
          `\\bgit_config_(?:key_\\d{1,3}|parameters)["']?\\s{0,4}=[^|;&\\n]{0,200}${HOOKSPATH}`,
          // An ANSI-C quoted argument with an escape: $'\\x2d\\x2dno-verify'.
          `${GIT_PRE}${SEP}\\$'[^'\\n]{0,200}\\\\(?:x[0-9a-f]{1,2}|[0-7]{1,3}|u[0-9a-f]{1,4})`,
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
      // The prefixes git accepts, and quotes or escapes the shell removes.
      bash("git commit --no-veri -m wip"),
      bash("git commit --no-verif -m wip"),
      bash("git push --no-veri origin main"),
      bash('git commit --no-"verify" -m wip'),
      bash("git commit --n''''o-ver''''ify -m wip"),
      bash("git commit --no-ver\\ify -m wip"),
      bash("git commit $'\\x2d\\x2dno-verify' -m wip"),
      bash(`git\${IFS}commit\${IFS}--no-verify`),
      pwsh("git commit “--no-verify” -m wip"),
      pwsh("git commit\u0085--no-verify -m wip"),
      // n inside a short cluster, as a whole argument.
      bash("git commit -nm wip"),
      bash("git commit -anm wip"),
      bash("git commit -sn -m wip"),
      bash('git commit "-n" -m wip'),
      bash("git commit $'-n' -m wip"),
      // A hooks folder chosen for one command, on the command line or in git's environment.
      bash("git -c core.hooksPath=/dev/null commit -m wip"),
      bash("git -c core.hooksPath= commit -m wip"),
      bash('git -c "core.hooksPath=/dev/null" commit -m wip'),
      bash("git -C /repo -c core.hooksPath=/dev/null push origin main"),
      bash("git -c core.hooks''Path=/dev/null commit -m wip"),
      bash("git -c core.hooks''''Path=/dev/null commit -m wip"),
      bash('git -c "core"."hooksPath"=/dev/null commit -m wip'),
      bash("git -c core.hooks\\Path= commit -m wip"),
      bash("git -c \\\n core.hooksPath=/dev/null commit -m wip"),
      bash("git --config-env=core.hooksPath=E commit -m wip"),
      bash(
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m wip",
      ),
      bash("GIT_CONFIG_PARAMETERS=\"'core.hooksPath'='/dev/null'\" git commit -m wip"),
      pwsh("$env:GIT_CONFIG_KEY_0 = 'core.hooksPath'; git commit -m wip"),
      mcp({ command: 'git commit --no-verify -m "wip"' }),
      // The same command under the other generic argument names, on an unmapped tool.
      mcp({ cmd: 'git commit --no-verify -m "wip"' }),
      mcp({ script: 'git commit --no-verify -m "wip"' }),
      // A mapped tool: `MCP_COMMAND_FIELDS` names the field that runs it.
      mcp({ command: 'git commit --no-verify -m "wip"' }, "mcp__iterm__write_to_terminal"),
    ],
    allow: [
      mentionInSearch("git commit --no-verify -m wip"),
      mentionInEcho("git commit --no-verify -m wip"),
      mentionInPost("git commit --no-verify -m wip"),
      bash('git commit -m "add the thing"'),
      bash("git push origin main"),
      bash("mvn -DskipTests package"),
      bash("git commit --amend --no-edit"),
      // --no-verb is --no-verbose, and --no-v … --no-ver are rejected by git as ambiguous.
      bash("git commit --no-verb -m wip"),
      bash("git commit --no-status -m wip"),
      bash("git push --no-thin origin main"),
      // n after -m is the message, and a flag-like word inside a quoted message is text.
      bash("git commit -mn"),
      bash("git commit -am wip"),
      bash('git commit -m "add -enable flag"'),
      bash('git commit -m "remove -only path"'),
      bash("git commit -m $'line one\\nline two'"),
      bash("git -c core.pager=cat log"),
      bash("git -c core.editor=vim commit"),
    ],
  },
};
