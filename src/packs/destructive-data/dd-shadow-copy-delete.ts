// cspell:words bbcdedit bcdedit bvssadmin bwbadmin recoveryenabled shadowcopy systemstatebackup tmutil vssadmin wbadmin

import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Deleting Windows shadow copies is the signature move of every ransomware family
 * there is: it removes the only local path back from an encrypted or wiped disk.
 * Nothing a coding agent legitimately does requires it.
 *
 * The `allow` fixtures are the read-only siblings of the same tools, because
 * `vssadmin list shadows` is a reasonable thing to run while diagnosing a backup.
 */
export const ddShadowCopyDelete: Rule = {
  id: "dd.shadow-copy-delete",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  title: "Deleting Windows shadow copies or recovery data",
  description:
    'Deletes Windows shadow copies, the backup catalog, or the recovery boot entry — the standard opening move of ransomware, because it removes the only local route back from an encrypted disk. There is no legitimate reason for a coding agent to run any of it. Does NOT match the read-only siblings (`vssadmin list shadows`, `wbadmin get status`, `bcdedit /enum`), which are reasonable while diagnosing a backup. Windows-only by nature; the equivalent on macOS (`tmutil delete`) is not covered. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bvssadmin\\b[^|;&]*\\bdelete\\s+shadows\\b",
          "\\bwbadmin\\s+delete\\s+(catalog|systemstatebackup)\\b",
          "\\bbcdedit\\b[^|;&]*recoveryenabled\\s+no\\b",
          "\\bwmic\\b[^|;&]*shadowcopy\\s+delete\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      pwsh("vssadmin delete shadows /all /quiet"),
      pwsh("wbadmin delete catalog -quiet"),
      pwsh("bcdedit /set {default} recoveryenabled no"),
      bash("wmic shadowcopy delete"),
    ],
    allow: [
      ...mentions("vssadmin delete shadows /all /quiet"),
      pwsh("vssadmin list shadows"),
      pwsh("wbadmin get status"),
      pwsh("bcdedit /enum"),
      pwsh("Get-ComputerRestorePoint"),
    ],
  },
};
