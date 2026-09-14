import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The id has no dotted pack prefix. Rule ids are stable identifiers, so it is not
 * renamed to match the others.
 */
export const blockDestructiveSql: Rule = {
  id: "block-destructive-sql",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  title: "Block destructive SQL in production",
  description:
    'Blocks shell commands that execute destructive SQL DDL — DROP TABLE, TRUNCATE or DROP DATABASE. The two-word phrases are matched in any case with any spacing. Bare TRUNCATE is matched only in UPPER case, and this rule is therefore CASE-SENSITIVE on that arm by design: lower-case `truncate` is also the coreutils binary and a common identifier, so matching it would block routine work — the cost is that a lower-case `truncate users;` without the `table` keyword is NOT caught. A command naming a read-only search or history tool (grep, rg, ag, ack, git commit/log/grep/blame/show) is left alone, because searching for the words is not executing them; a compound command that both searches and executes is therefore missed. Shell commands only: SQL issued from inside application code is invisible here. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        detail_matches: [
          "\\bdrop\\s+table\\b",
          "\\bdrop\\s+database\\b",
          "\\btruncate\\s+table\\b",
        ],
      },
      { kind: "execute_tool", detail_contains: ["TRUNCATE"] },
    ],
    none_of: [
      ...QUOTED_MENTION,
      {
        kind: "execute_tool",
        detail_matches: [
          "\\b(grep|egrep|fgrep|rg|ripgrep|ag|ack)\\b",
          "\\bgit\\s+(commit|log|grep|blame|show)\\b",
        ],
      },
    ],
  },
  fixtures: {
    block: [
      bash('psql -c "DROP TABLE users;"'),
      bash("psql -h db.internal -c 'TRUNCATE TABLE sessions;'"),
      bash("mysql -e 'drop database app;'"),
      bash("psql -c 'Drop Table sessions;'"),
    ],
    allow: [
      ...mentions("psql -c DROP TABLE users;"),
      bash("grep -rn TRUNCATE db/migrations/"),
      bash('git commit -m "add TRUNCATE step to the runbook"'),
      bash("psql -c 'SELECT * FROM users;'"),
      bash("truncate -s 0 /var/log/app.log"),
      bash("pnpm vitest run src/lib/truncate.test.ts"),
    ],
  },
};
