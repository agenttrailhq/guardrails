// cspell:words HISTFILE HISTSIZE journalctl reflog
import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Erasing the record of what was run.
 *
 * Not destructive to the project, but destructive to the trail — clearing shell history, vacuuming
 * the system journal, wiping `/var/log`, or expiring git's reflog so a rewrite leaves nothing to
 * recover from. Each is occasionally legitimate, which is why it asks rather than blocks.
 */
export const gbAuditTrailPurge: Rule = {
  id: "gb.audit-trail-purge",
  category: "safety-bypass",
  severity: "high",
  defaultAction: "require_approval",
  title: "Erasing shell history or system logs",
  description:
    'Holds a command that erases the record of what ran: `history -c` / `-w`, `unset HISTFILE`, `HISTFILE=/dev/null`, `HISTSIZE=0`, `set +o history`, PowerShell\'s `Clear-History`; deleting or truncating a `*_history` file (`rm`, `truncate`, `shred`, `: >`); `journalctl --vacuum-time` / `--vacuum-size` / `--vacuum-files` / `--rotate`; `rm -rf`, `truncate` or `shred` against `/var/log`; and `git reflog expire --expire=now` or `git gc --prune=now`, which drop the safety net a history rewrite would otherwise leave. A READ is not matched: `history` on its own, `history | tail`, `journalctl --since`, `git reflog`, `git reflog show`, and a plain `git gc`. MISSES `HISTFILE` unset in a shell profile rather than at the prompt, a log truncated with an editor or a file tool, and a purge run by a tool other than these. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bhistory\\s+-[cw]\\b",
          "\\b(?:unset\\s+HISTFILE|HISTFILE\\s*=\\s*/dev/null|HISTSIZE\\s*=\\s*0|set\\s+\\+o\\s+history|clear-history)\\b",
          "(?:\\brm\\b|\\btruncate\\b|\\bshred\\b|:\\s*>)[^|;&]*_history\\b",
          "\\bjournalctl\\b[^|;&]*--(?:vacuum-(?:time|size|files)|rotate)\\b",
          "\\b(?:rm\\s+-rf|truncate|shred)\\b[^|;&]*/var/log\\b",
          "\\bgit\\s+reflog\\s+expire\\b[^|;&]*--expire(?:=|\\s+)now\\b",
          "\\bgit\\s+gc\\b[^|;&]*--prune(?:=|\\s+)now\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("history -c"),
      bash("history -w"),
      bash("unset HISTFILE"),
      bash("export HISTFILE=/dev/null"),
      bash("HISTSIZE=0"),
      bash("set +o history"),
      bash("rm -f ~/.bash_history"),
      bash("truncate -s 0 ~/.zsh_history"),
      bash(": > ~/.bash_history"),
      bash("journalctl --vacuum-time=1s"),
      bash("journalctl --rotate"),
      bash("rm -rf /var/log/*"),
      bash("git reflog expire --expire=now --all"),
      bash("git gc --prune=now"),
      pwsh("Clear-History"),
    ],
    allow: [
      ...mentions("history -c"),
      bash("history"),
      bash("history | tail -50"),
      bash("cat ~/.bash_history"),
      bash("journalctl --since today -u nginx"),
      bash("journalctl -u app -f"),
      bash("git reflog"),
      bash("git reflog show HEAD"),
      bash("git gc"),
      bash("tail -f /var/log/syslog"),
      bash("ls /var/log"),
    ],
  },
};
