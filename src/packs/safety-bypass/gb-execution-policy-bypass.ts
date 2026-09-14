// cspell:words ecutionpolicy executionpolicy

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The Windows half of this pack. `-ExecutionPolicy Bypass` is the flag in every
 * PowerShell-based malware loader there is, and it is also occasionally what a
 * developer needs — hence a hold rather than a block.
 */
export const gbExecutionPolicyBypass: Rule = {
  id: "gb.execution-policy-bypass",
  category: "safety-bypass",
  severity: "high",
  defaultAction: "require_approval",
  title: "Bypassing the PowerShell execution policy",
  description:
    'Holds `Set-ExecutionPolicy Bypass/Unrestricted` and the `-ExecutionPolicy Bypass` launch flag, which together are the opening line of essentially every PowerShell-based loader. It is also occasionally what a developer legitimately needs, which is why it holds rather than blocks. Does NOT match reading the policy (`Get-ExecutionPolicy`), setting it to RemoteSigned, or an ordinary `powershell -Command`. Windows-only by nature. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bset-executionpolicy\\b[^|;&]*\\b(bypass|unrestricted)\\b",
          "\\b(powershell|pwsh)(\\.exe)?\\b[^|;&]*-ex(ecutionpolicy)?\\s+(bypass|unrestricted)\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      pwsh("Set-ExecutionPolicy Bypass -Scope Process -Force"),
      pwsh("powershell.exe -ExecutionPolicy Bypass -File .\\setup.ps1"),
      bash("pwsh -ExecutionPolicy Unrestricted -File setup.ps1"),
    ],
    allow: [
      ...mentions("Set-ExecutionPolicy Bypass -Scope Process -Force"),
      pwsh("Get-ExecutionPolicy"),
      pwsh("Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"),
      pwsh('powershell -Command "Get-Date"'),
      pwsh("Get-Process | Select-Object -First 5"),
    ],
  },
};
