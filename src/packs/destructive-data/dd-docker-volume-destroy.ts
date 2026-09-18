import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `docker compose down -v` is one character away from `docker compose down`, and
 * the character deletes the database. That is the entire reason this rule exists,
 * and it is why the neighboring command without `-v` is the `allow` fixture.
 */
export const ddDockerVolumeDestroy: Rule = {
  id: "dd.docker-volume-destroy",
  category: "destructive-data",
  severity: "high",
  defaultAction: "require_approval",
  title: "Docker volume deletion destroys container data",
  description:
    'Deletes Docker volumes, which is where a database running in a container keeps its data — `docker compose down -v` is one character away from `docker compose down` and the character is the difference between stopping the stack and losing its contents. Does NOT match `docker compose down` without the flag, `docker ps`, or `docker volume ls`, and it cannot tell a throwaway test volume from the one holding your local development data. Global flags between `docker` and its subcommand are tolerated (`docker --context <name> compose down -v`, `-H <host>`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bdocker${LEADING_FLAGS}\\s+volume\\s+rm\\b`,
          `\\bdocker${LEADING_FLAGS}(\\s+compose|-compose)?\\s+down\\b[^|;&]*\\s-v\\b`,
          `\\bdocker${LEADING_FLAGS}(\\s+compose|-compose)?\\s+down\\b[^|;&]*--volumes\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("docker compose down -v"),
      bash("docker-compose down --volumes"),
      bash("docker volume rm myapp_pgdata"),
      bash("docker --context prod compose down -v"),
      bash("docker -H unix:///var/run/docker.sock volume rm myapp_pgdata"),
    ],
    allow: [
      ...mentions("docker compose down -v"),
      bash("docker compose down"),
      bash("docker compose up -d"),
      bash("docker volume ls"),
      bash("docker ps -a"),
    ],
  },
};
