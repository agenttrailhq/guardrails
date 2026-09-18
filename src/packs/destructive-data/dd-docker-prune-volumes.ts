import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `docker system prune -f` is routine housekeeping. Adding `--volumes` changes it
 * into "delete every volume no container is currently using", which on a laptop
 * means every stopped project's database. Only the second is matched.
 */
export const ddDockerPruneVolumes: Rule = {
  id: "dd.docker-prune-volumes",
  category: "destructive-data",
  severity: "high",
  defaultAction: "require_approval",
  title: "Docker prune with volumes deletes unused data",
  description:
    'Prunes Docker volumes, deleting the data of every project whose containers are not currently running — on a developer laptop that is usually several other repositories\' databases. Routine housekeeping is deliberately NOT matched: `docker system prune -f` without `--volumes`, `docker image prune` and `docker builder prune` all pass. It cannot tell a volume you meant to discard from one you forgot was there. Global flags between `docker` and its subcommand are tolerated (`docker --context <name> system prune --volumes`, `-H <host>`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bdocker${LEADING_FLAGS}\\s+system\\s+prune\\b[^|;&]*--volumes\\b`,
          `\\bdocker${LEADING_FLAGS}\\s+volume\\s+prune\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("docker system prune --volumes -f"),
      bash("docker volume prune -f"),
      bash("docker system prune -a --volumes"),
      bash("docker --context prod system prune --volumes -f"),
    ],
    allow: [
      ...mentions("docker system prune --volumes -f"),
      bash("docker system prune -f"),
      bash("docker image prune -a"),
      bash("docker builder prune"),
      bash("docker volume ls"),
    ],
  },
};
