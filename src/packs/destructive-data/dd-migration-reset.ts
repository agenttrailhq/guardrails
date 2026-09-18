import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Every migration tool ships a command that means "throw the database away and
 * start again". They are all safe on a fresh local database and catastrophic
 * against anything with data in it, and the command text is identical in both
 * cases — the guard cannot see which database is configured, so it asks.
 */
export const ddMigrationReset: Rule = {
  id: "dd.migration-reset",
  category: "destructive-data",
  severity: "high",
  defaultAction: "require_approval",
  title: "Migration reset drops and rebuilds the schema",
  description:
    "Drops the schema and replays migrations from scratch — Prisma's `migrate reset`, Alembic's `downgrade base`, `rails db:reset`, Django's `flush`, Sequelize's `migrate:undo:all` and Drizzle's `drop`. Held for approval rather than blocked because it is the correct thing to do against a scratch database many times a day. The guard cannot see WHICH database is configured (no environment, no connection string reaches it), so it cannot distinguish a local reset from a production one. Does NOT match the forward commands (`migrate dev`, `migrate deploy`, `upgrade head`, `migrate:latest`). A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bprisma\\s+migrate\\s+reset\\b",
          "\\balembic\\s+downgrade\\s+base\\b",
          "\\b(rails|rake)\\s+db:(drop|reset)\\b",
          "\\b(django-admin|manage\\.py)\\s+flush\\b",
          "\\bsequelize\\s+db:migrate:undo:all\\b",
          "\\bknex\\s+migrate:rollback\\b[^|;&]*--all\\b",
          "\\bdrizzle-kit\\s+drop\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npx prisma migrate reset --force"),
      bash("alembic downgrade base"),
      bash("rails db:reset"),
      bash("python manage.py flush"),
    ],
    allow: [
      ...mentions("npx prisma migrate reset --force"),
      bash("npx prisma migrate dev --name add-users"),
      bash("npx prisma migrate deploy"),
      bash("alembic upgrade head"),
      bash("rails db:migrate"),
      bash("knex migrate:latest"),
    ],
  },
};
