// cspell:words bschtasks currentversion onlogon schtasks

import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Arranging to run again later, without anybody asking. A scheduled task, a
 * launch agent, an enabled service, or a line appended to a shell profile all do
 * the same thing: they outlive the session that created them.
 *
 * `crontab -l` and `cat ~/.zshrc` are the reads that sit beside them and must
 * stay quiet.
 */
export const psPersistence: Rule = {
  id: "ps.persistence",
  category: "privilege-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Arranging to run again after the session ends",
  description:
    'Holds a command that installs something which outlives the session — editing a crontab, loading a launch agent, creating a scheduled task, enabling a systemd unit, appending to a shell profile, or writing a Windows Run key. Reading the same things is deliberately NOT matched (`crontab -l`, `launchctl list`, `systemctl status`, `cat ~/.zshrc`). It cannot see WHAT is being scheduled, only that something is; and it MISSES persistence installed by writing a file with a file tool rather than by a shell command. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bcrontab\\s+-e\\b",
          "\\|\\s*crontab\\b",
          "\\blaunchctl\\s+(load|bootstrap)\\b",
          "\\bschtasks\\b[^|;&]*/create\\b",
          "\\bsystemctl\\s+enable\\b",
          ">>\\s*[^|;&]*\\.(bashrc|zshrc|profile|bash_profile|zprofile)\\b",
          "\\breg\\s+add\\b[^|;&]*currentversion\\\\run",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("crontab -e"),
      bash("echo '* * * * * /tmp/x.sh' | crontab -"),
      bash("systemctl enable myapp"),
      bash("echo 'export PATH=/tmp:$PATH' >> ~/.zshrc"),
      pwsh("schtasks /create /tn Updater /tr C:\\x.exe /sc onlogon"),
    ],
    allow: [
      ...mentions("crontab -e"),
      bash("crontab -l"),
      bash("systemctl status nginx"),
      bash("cat ~/.zshrc"),
      bash("launchctl list"),
    ],
  },
};
