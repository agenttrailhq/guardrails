// cspell:words dbo sqlcmd
import { MCP_SQL_TOOLS, QUOTED_MENTION, RUNS_SQL } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** DROP SCHEMA (any options, CASCADE included) and the DROP COLUMN action of ALTER TABLE. */
const SCHEMA_DROP = "\\bdrop\\s+(?:schema|column)\\b";

/**
 * Dropping a schema, or a column, in SQL. Held rather than blocked: resetting a scratch schema
 * or removing a retired column is ordinary work, and the guard cannot see which database the
 * client is connected to.
 */
export const ddSqlSchemaDrop: Rule = {
  id: "dd.sql-schema-drop",
  category: "destructive-data",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03", "LLM10"],
  title: "SQL that drops a schema or a table column",
  description:
    "Holds SQL that drops a schema (`DROP SCHEMA`, with or without `IF EXISTS` and `CASCADE`; in MySQL the same statement as `DROP DATABASE`) or drops a column (`ALTER TABLE … DROP COLUMN`), matched in any case with any spacing. Held for approval rather than blocked, because the guard cannot see which database the client is connected to, and a scratch schema reset is routine. On a shell command (Bash, PowerShell, and the Cursor and Codex shells mapped to them) it holds only when a SQL client is on the same command, the same list block-destructive-sql reads (`psql`, `mysql`, `sqlite3`, `sqlcmd` and others, including through `docker exec`, `kubectl exec`, `ssh` or an env prefix), so SQL that is only text is not held: a PR body, a heredoc that writes a migration file, a note. On MCP it reads only the SQL argument of the database tools `MCP_COMMAND_FIELDS` names (the PostgreSQL reference server's `query`, the SQLite reference server's `read_query`, `write_query` and `create_table`, Supabase's `execute_sql` and `apply_migration`, Neon's `run_sql`), under any server name. Not caught: a statement in a file the line does not show (`psql -f drop.sql`, a migration tool), a database MCP tool with another name, MySQL's `ALTER TABLE … DROP name` without the `COLUMN` keyword, and SQL issued from inside application code. A client word that appears only in text (`gh pr create --body \"… psql … DROP SCHEMA …\"`) is still held. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [`${RUNS_SQL}${SCHEMA_DROP}`],
      },
      // A database tool takes the statement itself: no client to require. `command` reads only
      // its SQL argument, not the rest of the call's input.
      {
        kind: "execute_tool",
        label: MCP_SQL_TOOLS,
        channel: "command",
        detail_matches: [SCHEMA_DROP],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash('psql -c "DROP SCHEMA public CASCADE;"'),
      bash("psql -c 'drop schema if exists scratch cascade'"),
      bash("mysql -e 'DROP SCHEMA app;'"),
      bash('psql -c "ALTER TABLE users DROP COLUMN email;"'),
      bash("psql -c 'alter table users drop column if exists email'"),
      bash('docker exec -it db psql -U app -c "Drop  Schema reporting CASCADE;"'),
      bash("psql app <<'EOF'\nALTER TABLE users DROP COLUMN legacy_id;\nEOF"),
      pwsh('sqlcmd -S localhost -Q "ALTER TABLE dbo.Users DROP COLUMN Email"'),
      mcp({ sql: "DROP SCHEMA public CASCADE;" }, "mcp__postgres__query"),
      mcp({ query: "ALTER TABLE cache DROP COLUMN payload;" }, "mcp__sqlite__write_query"),
      mcp(
        { project_id: "proj", query: "ALTER TABLE users DROP COLUMN email;" },
        "mcp__supabase__execute_sql",
      ),
      mcp({ project_id: "proj", sql: "drop schema staging cascade" }, "mcp__neon__run_sql"),
    ],
    allow: [
      ...mentions("psql -c DROP SCHEMA public CASCADE;"),
      bash('psql -c "CREATE SCHEMA reporting;"'),
      bash('psql -c "ALTER TABLE users ADD COLUMN email text;"'),
      bash('psql -c "ALTER TABLE users ALTER COLUMN email DROP DEFAULT;"'),
      bash('psql -c "ALTER TABLE users DROP CONSTRAINT users_email_key;"'),
      bash('psql -c "SELECT schema_name FROM information_schema.schemata;"'),
      // SQL that is only text: no client is on the line.
      bash(
        "cat > migrations/0042_drop_email.sql <<'EOF'\nALTER TABLE users DROP COLUMN email;\nEOF",
      ),
      bash(
        'gh pr create --title "Retire the legacy schema" --body "This migration runs DROP SCHEMA legacy CASCADE after the backfill."',
      ),
      // An MCP tool that is not a database tool: its text is not SQL.
      mcp(
        { title: "Retire legacy", body: "Run DROP SCHEMA legacy CASCADE." },
        "mcp__issues__create_issue",
      ),
      mcp({ sql: "SELECT * FROM users;" }, "mcp__postgres__query"),
    ],
  },
};
