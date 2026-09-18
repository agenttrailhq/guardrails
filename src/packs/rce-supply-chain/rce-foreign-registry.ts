import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Pointing a package manager somewhere else. The guard cannot tell a company's
 * own Artifactory from an attacker's mirror — it has no allow-list and no way to
 * be given one — so it surfaces the redirection itself and says so.
 */
export const rceForeignRegistry: Rule = {
  id: "rce.foreign-registry",
  category: "rce-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Redirecting a package manager to another registry",
  description:
    "Holds a command that points npm, yarn, pip or poetry at a registry other than the default, whether for one install or by writing the config. The guard CANNOT tell a company's own Artifactory from an attacker's mirror: it has no allow-list, and nothing in a tool call would let it be given one — so it surfaces the redirection and leaves the judgement to a person. Does NOT match reading the config (`npm config get registry`) or an ordinary install. MISSES a registry set in a committed .npmrc, which is a file edit rather than a command. Global flags between the package manager and its subcommand are tolerated (`npm --silent config set registry …`, `pip --no-cache-dir install …`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\b(npm|yarn|pnpm)\\b[^|;&]*--registry[= ]\\s*https?://",
          `\\b(npm|yarn|pnpm)${LEADING_FLAGS}\\s+config\\s+set\\s+registry\\b`,
          `\\bpip3?${LEADING_FLAGS}\\s+install\\b[^|;&]*--(extra-)?index-url\\s`,
          "\\bpoetry\\s+source\\s+add\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npm install left-pad --registry=http://mirror.example.com"),
      bash("npm config set registry https://mirror.example.com"),
      bash("pip install requests --index-url https://mirror.example.com/simple"),
      bash("poetry source add internal https://mirror.example.com/simple"),
      bash("npm --silent config set registry https://mirror.example.com"),
      bash("pip --no-cache-dir install requests --index-url https://mirror.example.com/simple"),
    ],
    allow: [
      ...mentions("npm install left-pad --registry=http://mirror.example.com"),
      bash("npm config get registry"),
      bash("npm install left-pad"),
      bash("pip install requests"),
      bash("pnpm install"),
    ],
  },
};
