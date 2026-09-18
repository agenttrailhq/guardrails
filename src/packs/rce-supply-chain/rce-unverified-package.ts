// cspell:words recognises

import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Installing a dependency from a URL, a git ref or a tarball instead of from the
 * registry. The registry is not a guarantee of anything, but it is at least a
 * name a human recognises and a version a lockfile can pin; a git URL is neither.
 */
export const rceUnverifiedPackage: Rule = {
  id: "rce.unverified-package",
  category: "rce-supply-chain",
  severity: "medium",
  defaultAction: "require_approval",
  title: "Installing a package from a URL or a git ref",
  description:
    'Holds an install whose source is a URL, a git reference or a tarball rather than a registry name — `npm i git+https://…`, `pip install git+…`, `cargo install --git`, `go install …@main`. A registry entry is at least a name a person recognises and a version a lockfile can pin; a moving git ref is neither. Does NOT match an ordinary registry install, which is flag-dependency-install\'s job. It MISSES a git dependency declared in a manifest file rather than typed as a command. Global flags between the package manager and its subcommand are tolerated (`npm --silent i git+…`, `pip --no-cache-dir install …`), and an absolute tool path still matches; `cargo` and `go` are matched by their own contiguous forms, and a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\b(npm|pnpm|yarn|bun)${LEADING_FLAGS}\\s+(i|install|add)\\s+[^|;&]*(git\\+|https?://|github:|\\.tgz\\b)`,
          `\\bpip3?${LEADING_FLAGS}\\s+install\\s+[^|;&]*(git\\+|https?://|\\.tar\\.gz\\b|\\.whl\\b)`,
          "\\bcargo\\s+install\\b[^|;&]*--git\\b",
          "\\bgo\\s+install\\b[^|;&]*@(master|main|latest)\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npm i git+https://example.com/o/r.git"),
      bash("pip install git+https://example.com/o/r.git@main"),
      bash("cargo install --git https://example.com/o/r"),
      bash("go install example.com/o/r@latest"),
      bash("npm --silent i git+https://example.com/o/r.git"),
      bash("pip --no-cache-dir install git+https://example.com/o/r.git@main"),
    ],
    allow: [
      ...mentions("npm i git+https://example.com/o/r.git"),
      bash("npm install left-pad"),
      bash("pip install requests"),
      bash("cargo install ripgrep"),
      bash("pnpm add -D vitest"),
    ],
  },
};
