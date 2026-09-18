// cspell:words childitem

import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Printing the environment, or a dotenv file, into the terminal. The near-miss
 * that must stay quiet is `env VAR=value <command>` — the POSIX way to set one
 * variable for one command, which has nothing to do with printing anything.
 */
export const seEnvPrint: Rule = {
  id: "se.env-print",
  category: "secret-exposure",
  severity: "medium",
  defaultAction: "warn",
  title: "Printing the environment or a dotenv file",
  description:
    'Surfaces the environment or a dotenv file being printed into the terminal, where it lands in scrollback and in the session transcript. Committed placeholder files are excluded (`.env.example`, `.env.sample`, `.env.template`). Does NOT match the POSIX `env VAR=value <command>` form, which sets a variable rather than printing one, and does NOT match a `.env` opened by a file tool — that travels the file channel and is covered by block-env-file-read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bprintenv\\b",
          "\\benv\\s*\\|",
          "\\bcat\\s+[^|;&]*\\.env\\b",
          "\\bexport\\s+-p\\b",
          "\\bget-childitem\\s+env:",
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: ["\\.env\\.(example|sample|template)\\b"],
      },
    ],
  },
  fixtures: {
    block: [
      bash("cat .env"),
      bash("cat apps/api/.env.production"),
      bash("printenv"),
      bash("env | sort"),
      pwsh("Get-ChildItem Env:"),
    ],
    allow: [
      ...mentions("cat .env"),
      bash("cat .env.example"),
      bash("env NODE_ENV=test pnpm vitest run"),
      bash("cat package.json"),
      bash("ls -la"),
    ],
  },
};
