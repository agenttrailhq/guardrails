import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The flags whose own names admit what they do. If a tool made you type
 * `--accept-data-loss`, the tool has already told you this needs a human.
 */
export const ddAcceptDataLoss: Rule = {
  id: "dd.accept-data-loss",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  title: "A flag that explicitly accepts data loss",
  description:
    'Matches the flags whose own names admit the consequence — `--accept-data-loss` (Prisma), `--force-reset`, and `prisma db push --force`. A tool that makes you type those words has already decided a human should be in the loop. Does NOT match `prisma db push` without a flag, which is the ordinary spelling, and it cannot tell a scratch database from a real one because no connection string reaches the guard. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "--accept-data-loss\\b",
          "--force-reset\\b",
          "\\bprisma\\s+db\\s+push\\b[^|;&]*--force\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npx prisma db push --accept-data-loss"),
      bash("npx prisma migrate reset --force-reset"),
      bash("npx prisma db push --force"),
    ],
    allow: [
      ...mentions("npx prisma db push --accept-data-loss"),
      bash("npx prisma db push"),
      bash("npx prisma generate"),
      bash("pnpm db:push"),
      bash("npx prisma studio"),
    ],
  },
};
