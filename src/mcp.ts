/**
 * Which arguments of an MCP tool call execute, as plain data.
 *
 * No zod here, so the corpus entry (`./rules.ts`) can re-export it and stay validator-free.
 *
 * A condition on the `command` channel (see `CHANNELS` in `schema.ts`) reads only the text a
 * call runs. For `Bash` and `PowerShell` that is the whole command. For an MCP call it is the
 * argument fields that execute, chosen with these two tables:
 *
 * - **A mapped tool** (its tool segment is a key of `MCP_COMMAND_FIELDS`): the listed top-level
 *   fields that hold a non-empty string, joined with a newline. A tool with none of them present
 *   has no command text.
 * - **An unmapped tool**: whichever of `MCP_GENERIC_COMMAND_FIELDS` are top-level non-empty
 *   strings, joined the same way. A tool with none of them has no command text, so no `command`
 *   condition can match it. Free text such as a ticket description, a chat message or a search
 *   query is never read.
 *
 * A condition on the `content` channel reads the call's whole serialized input either way.
 *
 * ── Keyed by tool, not by server ────────────────────────────────────────────
 *
 * An MCP tool is named `mcp__<server>__<tool>`. The server segment is whatever the user called
 * the server in their own configuration, and some clients report every tool under one fixed
 * server name, so only the tool segment is stable. A key here is that segment, matched exactly.
 *
 * ── Adding a tool ───────────────────────────────────────────────────────────
 *
 * List the fields the server's published input schema documents as executing, and add a block
 * fixture that carries a command in one of them. A mapped entry is worth adding when the
 * executing field has a name the generic list does not cover (`input`, `query`,
 * `command_line`), and it also stops a tool's non-executing `command`, `cmd`, `sql` or `script`
 * field from being read: a mapped tool never falls back to the generic list. Only string fields
 * are read, so a field that holds an array of statements is not listed.
 */

/** Top-level argument fields that execute, keyed by an MCP tool name's tool segment. */
export const MCP_COMMAND_FIELDS: Readonly<Record<string, readonly string[]>> = {
  // Desktop Commander: a shell command, then input written to a running process.
  start_process: ["command"],
  interact_with_process: ["input"],
  // Desktop Commander, earlier releases.
  execute_command: ["command"],
  // iTerm: text written to the active terminal, usually a command.
  write_to_terminal: ["command"],
  // mcp-server-commands: a shell command line. Its `argv` form is an array and is not read.
  run_process: ["command_line"],
  // mcp-server-commands, earlier releases.
  run_command: ["command"],
  // The PostgreSQL reference server.
  query: ["sql"],
  // The SQLite reference server.
  read_query: ["query"],
  write_query: ["query"],
  create_table: ["query"],
  // Supabase.
  execute_sql: ["query"],
  apply_migration: ["query"],
  // Neon.
  run_sql: ["sql"],
};

/** The argument fields read as command text on an MCP tool that `MCP_COMMAND_FIELDS` does not map. */
export const MCP_GENERIC_COMMAND_FIELDS: readonly string[] = ["command", "cmd", "sql", "script"];
