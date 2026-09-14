// cspell:words createdb dropdatabase mongosh

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Dropping a database from the shell, rather than from inside SQL — which is
 * `block-destructive-sql`'s job. The two do not overlap: `dropdb myapp` contains
 * no `drop database` phrase and would sail past that rule entirely.
 */
export const ddDatabaseDrop: Rule = {
  id: "dd.database-drop",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  title: "Dropping a database from the command line",
  description:
    'Deletes a whole database through a shell tool rather than through SQL — `dropdb`, MongoDB\'s `dropDatabase()`, and the AWS RDS delete calls. It is the companion to block-destructive-sql, which sees the SQL statement but not `dropdb myapp`, because that command contains no DROP DATABASE phrase. Known over-match: `dropdb --help` is matched too, since the rule reads command text and cannot tell a help flag from a target. It does NOT cover a drop issued by application code or by a migration tool (see dd.migration-reset). A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bdropdb\\b",
          "\\bdb\\.dropdatabase\\(",
          "\\bdb\\.[\\w.]+\\.drop\\(\\)",
          "\\baws\\s+rds\\s+delete-db-(instance|cluster)\\b",
          "\\bmongo(sh)?\\b[^|;&]*--eval\\b[^|;&]*\\bdrop\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("dropdb myapp_production"),
      bash("mongosh --eval 'db.dropDatabase()'"),
      bash("aws rds delete-db-instance --db-instance-identifier prod-1"),
    ],
    allow: [
      ...mentions("dropdb myapp_production"),
      bash("createdb myapp_test"),
      bash("pg_dump myapp > dump.sql"),
      bash("aws rds describe-db-instances"),
      bash("mongosh --eval 'db.stats()'"),
    ],
  },
};
