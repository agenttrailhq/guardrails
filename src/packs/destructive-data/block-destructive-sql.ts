// cspell:words clickhouse cqlsh dbmate duckdb liquibase litecli mycli mysqlsh PGPASSWORD pgcli snowsql sqlcmd sqlplus usql
import { QUOTED_MENTION, RUNS_SQL } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The id has no dotted pack prefix. Guardrail ids are stable identifiers, so it is not
 * renamed to match the others.
 */
export const blockDestructiveSql: Rule = {
  id: "block-destructive-sql",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  owasp: ["ASI02", "LLM03", "LLM10"],
  title: "Block destructive SQL",
  description:
    'Blocks commands that execute destructive SQL DDL — DROP TABLE, TRUNCATE or DROP DATABASE. On a shell command (Bash, PowerShell, and the Cursor and Codex shells mapped to them) it blocks only when a SQL client is on the same command — `psql`, `pgcli`, `mysql`, `mysqlsh`, `mariadb`, `mycli`, `sqlite3`, `litecli`, `sqlcmd`, `sqlplus`, `usql`, `clickhouse-client`, `cockroach sql`, `snowsql`, `bq query`, `cqlsh`, `duckdb`, `prisma db execute` or `wrangler d1 execute`, including through `docker exec`, `kubectl exec`, `ssh` or an env prefix — so SQL that is only TEXT is not blocked: a PR or issue body, a heredoc or `printf` that writes a migration file, a note. With a client on the line, `TRUNCATE` is matched in any case with or without `TABLE`. Not caught on a shell: a statement in a file the line does not show (`psql -f drop.sql`, `psql < drop.sql`, a migration tool such as `flyway`, `liquibase`, `dbmate`, `prisma migrate` or `alembic`), a script that runs a client the line does not name, a client this list does not name, and a client word that appears only in text (`gh pr create --body "… psql … DROP TABLE …"` is still blocked). On an MCP tool (`mcp__*`), which takes the statement itself as its input, the two-word phrases are matched in any case with any spacing, and bare TRUNCATE only in UPPER case, so that arm is CASE-SENSITIVE by design: lower-case `truncate` is also a common identifier, and the cost is that a lower-case `truncate users;` without the `table` keyword is NOT caught there. A search for the words (`grep -rn TRUNCATE db/`, `cat runbook.md | grep -n TRUNCATE`) has no client on it and is not matched; text a search finds and pipes into a client (`grep "DROP TABLE x" notes.sql | psql`) is blocked. So is a read-only query whose output is searched for the words (`psql -c "select query from pg_stat_activity" | grep -i "drop table"`), because the client and the words share the line. SQL issued from inside application code is invisible here. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      // Shell: only when a SQL client is on the line. `truncate` in any case, because the
      // client requirement is what keeps coreutils `truncate -s` and identifiers out.
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          `${RUNS_SQL}\\bdrop\\s+table\\b`,
          `${RUNS_SQL}\\bdrop\\s+database\\b`,
          `${RUNS_SQL}\\btruncate\\s+(?!-)\\w`,
        ],
      },
      // An MCP database tool takes the statement itself as its input: no client to require.
      {
        kind: "execute_tool",
        label: "mcp__*",
        detail_matches: [
          "\\bdrop\\s+table\\b",
          "\\bdrop\\s+database\\b",
          "\\btruncate\\s+table\\b",
        ],
      },
      { kind: "execute_tool", label: "mcp__*", detail_contains: ["TRUNCATE"] },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash('psql -c "DROP TABLE users;"'),
      bash("psql -h db.internal -c 'TRUNCATE TABLE sessions;'"),
      bash("mysql -e 'drop database app;'"),
      bash("psql -c 'Drop Table sessions;'"),
      // A client reached through a wrapper or an env prefix, a heredoc fed to it, and
      // lower-case TRUNCATE once a client is on the line.
      bash('docker exec -it db psql -U app -c "DROP TABLE users;"'),
      bash("kubectl exec deploy/db -- mysql -e 'DROP DATABASE app;'"),
      bash("PGPASSWORD=x psql -h db -c 'drop table users'"),
      bash("psql app <<'EOF'\nDROP TABLE legacy_users;\nEOF"),
      bash("psql -c 'truncate sessions;'"),
      bash("psql -c 'TRUNCATE sessions;'"),
      bash("sqlite3 app.db 'DROP TABLE cache;'"),
      bash("npx wrangler d1 execute app --command 'DROP TABLE users'"),
      pwsh('sqlcmd -S localhost -Q "DROP DATABASE app"'),
      // Text a search finds, piped into a client.
      bash('grep -h "DROP TABLE users" notes.sql | psql app'),
      bash('rg -o "TRUNCATE TABLE sessions" notes.md | psql -d app'),
      bash('git show HEAD:x.sql | grep "DROP TABLE" | sqlite3 app.db'),
      // Accepted over-match: a read-only query whose output is searched for the words. A
      // client and the words are on one line, and nothing here can tell output from input.
      bash('psql -c "select query from pg_stat_activity" | grep -i "drop table"'),
      // Accepted over-match: history searched for a statement that names a client.
      bash("git log -p | grep 'psql -c \"DROP TABLE'"),
      // An MCP statement naming a schema that is also a search tool's name (`ag`).
      mcp({ sql: "DROP TABLE ag.users;" }),
      // A database server's SQL argument: the generic `sql` field on an unmapped tool, then
      // each mapped database tool in `MCP_COMMAND_FIELDS`.
      mcp({ sql: "DROP TABLE users;" }),
      mcp({ sql: "DROP TABLE users;" }, "mcp__postgres__query"),
      mcp({ query: "DROP TABLE sessions;" }, "mcp__sqlite__read_query"),
      mcp({ query: "DROP TABLE users;" }, "mcp__sqlite__write_query"),
      mcp(
        { query: "DROP TABLE IF EXISTS users; CREATE TABLE users (id INTEGER)" },
        "mcp__sqlite__create_table",
      ),
      mcp({ project_id: "proj", query: "TRUNCATE TABLE sessions;" }, "mcp__supabase__execute_sql"),
      mcp(
        { project_id: "proj", name: "drop_legacy_users", query: "DROP TABLE legacy_users;" },
        "mcp__supabase__apply_migration",
      ),
      mcp({ project_id: "proj", sql: "DROP DATABASE app;" }, "mcp__neon__run_sql"),
    ],
    allow: [
      ...mentions("psql -c DROP TABLE users;"),
      bash("grep -rn TRUNCATE db/migrations/"),
      bash("cat runbook.md | grep -n TRUNCATE"),
      bash("grep -rn \"psql -c 'DROP TABLE users'\" docs | head"),
      bash('git commit -m "add TRUNCATE step to the runbook"'),
      bash("psql -c 'SELECT * FROM users;'"),
      bash("truncate -s 0 /var/log/app.log"),
      bash("pnpm vitest run src/lib/truncate.test.ts"),
      // SQL that is only text: no client is on the line.
      bash(
        'gh pr create --title "Drop legacy tables" --body "This migration will DROP TABLE legacy_users after the backfill."',
      ),
      bash('gh issue comment 42 --body "TRUNCATE TABLE sessions runs nightly"'),
      bash("cat > migrations/0042_drop_legacy.sql <<'EOF'\nDROP TABLE legacy_users;\nEOF"),
      bash("printf '%s\\n' 'DROP DATABASE scratch;' > drop.sql"),
      pwsh("Set-Content -Path drop.sql -Value 'DROP TABLE legacy_users;'"),
      bash("psql -c 'SELECT count(*) FROM sessions;' && truncate -s 0 /var/log/app.log"),
    ],
  },
};
