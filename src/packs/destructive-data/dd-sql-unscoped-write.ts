// cspell:words dbo sqlcmd
import { MCP_SQL_TOOLS, QUOTED_MENTION, RUNS_SQL } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * No WHERE later in the same statement: a lookahead that stops at the next `;`, so a scoped
 * statement before or after does not lend this one its WHERE. Bounded at 1000 characters, so the
 * scan stays linear; a WHERE further away than that is not seen, and the statement is held.
 */
const NO_WHERE = "(?![^;]{0,1000}\\bwhere\\b)";

/** `DELETE FROM <table>` with no WHERE. */
const DELETE_ALL = `\\bdelete\\s+from\\b${NO_WHERE}`;

/**
 * `UPDATE <table> [[AS] alias] SET` with no WHERE. The table cannot hold a shell operator, so
 * `apt-get update && set -e` is not a table; `ONLY` fills the table slot and the table the alias
 * slot. An upsert's `DO UPDATE SET`, `ON DUPLICATE KEY UPDATE`, `FOR UPDATE` and `BEFORE UPDATE
 * ON` do not have a table followed by `SET`.
 */
const UPDATE_ALL = `\\bupdate\\s+[^\\s;&|<>]+(?:\\s+(?:as\\s+)?\\w+)?\\s+set\\b${NO_WHERE}`;

/**
 * A DELETE or an UPDATE that changes every row of a table. Held rather than blocked: clearing a
 * table in a local test database is routine, and the guard cannot see which database it is.
 */
export const ddSqlUnscopedWrite: Rule = {
  id: "dd.sql-unscoped-write",
  category: "destructive-data",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03", "LLM10"],
  title: "SQL DELETE or UPDATE with no WHERE clause",
  description:
    "Holds a SQL `DELETE FROM <table>` or `UPDATE <table> … SET` that has no `WHERE` later in the same statement, so it changes every row, matched in any case with any spacing. Each statement is judged on its own: a `;` ends it, so a scoped statement before or after does not lend it a `WHERE`. `DELETE … USING` and `UPDATE … FROM` without a `WHERE` are held, and so is `EXPLAIN ANALYZE`, which runs the statement. Held for approval rather than blocked, because clearing a table in a local test database is routine and the guard cannot see which database the client is connected to. On a shell command (Bash, PowerShell, and the Cursor and Codex shells mapped to them) it holds only when a SQL client is on the same command, the same list block-destructive-sql reads (`psql`, `mysql`, `sqlite3`, `sqlcmd` and others, including through `docker exec`, `kubectl exec`, `ssh` or an env prefix), so SQL that is only text is not held: a PR body, a heredoc that writes a seed file, a note. On MCP it reads only the SQL argument of the database tools `MCP_COMMAND_FIELDS` names (the PostgreSQL reference server's `query`, the SQLite reference server's `read_query`, `write_query` and `create_table`, Supabase's `execute_sql` and `apply_migration`, Neon's `run_sql`), under any server name, so a ticket or a message that quotes such a statement is not held. Not caught: any `WHERE` in the statement counts, including one inside a comment, a string or a subquery, and a tautology such as `WHERE 1=1`; a second `psql -c` whose statement has a `WHERE`; MySQL's `UPDATE a JOIN b … SET`; T-SQL's `DELETE TOP (n)` and `DELETE <table>` without `FROM`; a statement in a file the line does not show (`psql -f reset.sql`); a database MCP tool with another name; and SQL issued from inside application code. Over-matches, held anyway: a plain `EXPLAIN` of such a statement, which does not run it; a `WHERE` more than 1000 characters into the statement; a client word that appears only in text. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [`${RUNS_SQL}${DELETE_ALL}`, `${RUNS_SQL}${UPDATE_ALL}`],
      },
      // A database tool takes the statement itself: no client to require. `command` reads only
      // its SQL argument, not the rest of the call's input.
      {
        kind: "execute_tool",
        label: MCP_SQL_TOOLS,
        channel: "command",
        detail_matches: [DELETE_ALL, UPDATE_ALL],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash('psql -c "DELETE FROM sessions;"'),
      bash("psql -c 'delete  from sessions'"),
      bash("sqlite3 app.db 'DELETE FROM cache;'"),
      bash("mysql -e 'DELETE FROM audit_log'"),
      // A second statement with no WHERE after a scoped one.
      bash('psql -c "DELETE FROM sessions WHERE id = 1; DELETE FROM tokens;"'),
      bash('psql -c "DELETE FROM orders USING customers;"'),
      // A WHERE before the DELETE, in a CTE, does not scope it.
      bash('psql -c "WITH stale AS (SELECT id FROM jobs WHERE done) DELETE FROM jobs;"'),
      bash("psql -c \"UPDATE users SET plan = 'free';\""),
      bash("mysql -e 'update users u set u.active = 0'"),
      bash('psql -c "UPDATE ONLY users SET active = false;"'),
      bash('psql -c "UPDATE users AS u SET active = false;"'),
      bash('psql -c "UPDATE orders SET total = t.total FROM totals t;"'),
      bash("psql -c 'UPDATE \"Users\" SET active = false;'"),
      bash("psql app <<'EOF'\nUPDATE users SET plan = 'free';\nEOF"),
      bash('psql -c "EXPLAIN ANALYZE DELETE FROM sessions;"'),
      bash('docker exec -it db psql -U app -c "DELETE FROM users;"'),
      pwsh('sqlcmd -S localhost -Q "DELETE FROM dbo.Sessions"'),
      // Accepted over-match: a plain EXPLAIN does not run the statement.
      bash('psql -c "EXPLAIN DELETE FROM sessions;"'),
      mcp({ sql: "DELETE FROM users;" }, "mcp__postgres__query"),
      mcp({ query: "update users set plan = 'free'" }, "mcp__sqlite__write_query"),
      mcp({ project_id: "proj", query: "DELETE FROM sessions;" }, "mcp__supabase__execute_sql"),
      mcp({ project_id: "proj", sql: "UPDATE accounts SET balance = 0;" }, "mcp__neon__run_sql"),
    ],
    allow: [
      ...mentions("psql -c DELETE FROM sessions;"),
      bash('psql -c "DELETE FROM sessions WHERE expires_at < now();"'),
      bash("psql -c 'delete from sessions where id = 1'"),
      bash('psql -c "UPDATE users SET active = false WHERE id = 7;"'),
      bash("psql app <<'EOF'\nDELETE FROM sessions\nWHERE expires_at < now();\nEOF"),
      bash('psql -c "UPDATE orders SET total = t.total FROM totals t WHERE orders.id = t.id;"'),
      bash('psql -c "DELETE FROM orders USING customers c WHERE orders.customer_id = c.id;"'),
      bash('psql -c \'UPDATE "Users" SET active = false WHERE "id" = 1;\''),
      bash('psql -c "SELECT * FROM users;"'),
      bash('psql -c "EXPLAIN SELECT * FROM users;"'),
      bash(
        'psql -c "INSERT INTO counts (id, n) VALUES (1, 1) ON CONFLICT (id) DO UPDATE SET n = counts.n + 1;"',
      ),
      bash("mysql -e 'INSERT INTO counts VALUES (1, 1) ON DUPLICATE KEY UPDATE n = n + 1'"),
      bash('psql -c "SELECT * FROM jobs FOR UPDATE SKIP LOCKED;"'),
      bash(
        'psql -c "CREATE TRIGGER touch BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION touch();"',
      ),
      bash("psql -c 'GRANT UPDATE ON users TO app;'"),
      bash("apt-get update && set -e && psql -c 'SELECT 1;'"),
      // SQL that is only text: no client is on the line.
      bash("cat > seed.sql <<'EOF'\nDELETE FROM sessions;\nEOF"),
      bash('gh issue comment 42 --body "Ran UPDATE users SET plan = free to fix the import."'),
      // An MCP tool that is not a database tool: its text is not SQL.
      mcp(
        {
          title: "Reset plans",
          body: "Run UPDATE users SET plan = 'free', then DELETE FROM sessions.",
        },
        "mcp__issues__create_issue",
      ),
      mcp({ sql: "DELETE FROM users WHERE id = 1;" }, "mcp__postgres__query"),
      mcp({ query: "SELECT * FROM users;" }, "mcp__sqlite__read_query"),
    ],
  },
};
