import { LEADING_FLAGS, QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * FILED BY HARM: a new third-party dependency is a supply-chain event. It
 * executes nothing remote by itself, so it is not an `rce-*` rule.
 */
export const flagDependencyInstall: Rule = {
  id: "flag-dependency-install",
  category: "privilege-supply-chain",
  severity: "low",
  defaultAction: "warn",
  title: "Flag new dependency installs",
  description:
    'Surfaces a new third-party dependency being added — npm/pnpm/yarn/bun, pip/pipx/poetry/uv, gem, cargo, go get, composer, bundle, dotnet and mix. Non-blocking. Each form requires a PACKAGE ARGUMENT, so a lockfile restore that adds nothing — `npm ci`, `pnpm install`, `pnpm install --frozen-lockfile` — is deliberately not flagged. A global flag between the tool and its subcommand is tolerated (`npm --silent install pkg`, `pnpm -C apps/web add react`). MISSES a package named after more than one flag between the subcommand and the package, an install run through a wrapper, a dependency added by hand-editing a manifest, and the system package managers (apt, brew, apk), which install machine software rather than project dependencies. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        detail_matches: [
          `\\b(npm|pnpm|yarn|bun)${LEADING_FLAGS}\\s+(install|add|i)\\s+(--?[\\w-]+\\s+)?@?[a-z0-9][\\w.@/-]*`,
        ],
      },
      {
        kind: "execute_tool",
        detail_matches: [
          `\\b(pip3?|pipx|poetry|uv)${LEADING_FLAGS}\\s+(install|add)\\s+(--?[\\w-]+\\s+)?[a-z0-9@][\\w.@/-]*`,
        ],
      },
      {
        kind: "execute_tool",
        detail_matches: [
          `\\bgem${LEADING_FLAGS}\\s+install\\s+[a-z0-9]`,
          `\\bcargo${LEADING_FLAGS}\\s+(install|add)\\s+[a-z0-9]`,
          `\\bgo${LEADING_FLAGS}\\s+get\\s+[a-z0-9]`,
          `\\bcomposer${LEADING_FLAGS}\\s+require\\s+[a-z0-9]`,
          `\\bbundle${LEADING_FLAGS}\\s+add\\s+[a-z0-9]`,
          `\\bdotnet${LEADING_FLAGS}\\s+add\\s+package\\s+[a-z0-9]`,
          `\\bmix${LEADING_FLAGS}\\s+deps\\.get\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("npm install left-pad"),
      bash("npm i left-pad"),
      bash("pnpm add -D vitest"),
      bash("pip3 install requests"),
      bash("cargo add serde"),
      bash("go get github.com/pkg/errors"),
      bash("npm --silent install left-pad"),
      bash("pnpm -C apps/web add react"),
    ],
    allow: [
      ...mentions("npm install left-pad"),
      bash("npm ci"),
      bash("pnpm install"),
      bash("pnpm install --frozen-lockfile"),
      bash("npm run build"),
      bash("cargo build --workspace"),
    ],
  },
};
