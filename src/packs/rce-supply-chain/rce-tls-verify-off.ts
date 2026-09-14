// cspell:words sslverify

import { GIT_TEXT_MENTION, PRINT_MENTION, SEARCH_MENTION } from "../../exemptions.js";
import { bash, mentionInCommit, mentionInEcho, mentionInSearch } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Turning off certificate verification. Every one of these flags converts an
 * encrypted channel into one anybody on the path can rewrite, which is how a
 * dependency download becomes an arbitrary payload.
 */
export const rceTlsVerifyOff: Rule = {
  id: "rce.tls-verify-off",
  category: "rce-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Disabling TLS certificate verification",
  description:
    "Holds a command that switches off certificate verification — curl's -k/--insecure, wget's --no-check-certificate, NODE_TLS_REJECT_UNAUTHORIZED=0, git's http.sslVerify=false, pip's --trusted-host, npm's --strict-ssl=false. Each turns an encrypted channel into one anyone on the path can rewrite, which is how a dependency download becomes an arbitrary payload. Does NOT match ordinary https requests. Known over-match: any curl short-flag cluster containing the letter k is treated as -k, since the guard parses no argv. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt. `curl --data` is NOT one of those carriers here, because this rule's own trigger IS a `curl`/`wget` flag.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bcurl\\b[^|;&]*\\s-[a-z]*k[a-z]*(\\s|$)",
          "\\bcurl\\b[^|;&]*--insecure\\b",
          "\\bwget\\b[^|;&]*--no-check-certificate\\b",
          "\\bnode_tls_reject_unauthorized\\s*=\\s*0",
          "\\bhttp\\.sslverify\\s*=\\s*false",
          "\\bpip3?\\s+install\\b[^|;&]*--trusted-host\\b",
          "\\bnpm\\b[^|;&]*--strict-ssl[= ]\\s*false\\b",
        ],
      },
    ],
    none_of: [SEARCH_MENTION, GIT_TEXT_MENTION, PRINT_MENTION],
  },
  fixtures: {
    block: [
      bash("curl -k https://internal.example.com/api"),
      bash("wget --no-check-certificate https://example.com/x.tgz"),
      bash("NODE_TLS_REJECT_UNAUTHORIZED=0 pnpm install"),
      bash("git -c http.sslVerify=false clone https://example.com/repo.git"),
    ],
    allow: [
      mentionInCommit("curl -k https://internal.example.com/api"),
      mentionInSearch("curl -k https://internal.example.com/api"),
      mentionInEcho("curl -k https://internal.example.com/api"),
      bash("curl -fsSL https://example.com/data.json -o data.json"),
      bash("wget https://example.com/x.tgz"),
      bash("git -c core.pager=cat log --oneline"),
      bash("pip install requests"),
    ],
  },
};
