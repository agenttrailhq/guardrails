import { LEADING_FLAGS, QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Helm's destructive verbs. `helm upgrade --install` — the idempotent deploy
 * everybody actually uses — is the near-miss, and it stays quiet.
 */
export const piHelmRelease: Rule = {
  id: "pi.helm-release",
  category: "prod-infra",
  severity: "high",
  defaultAction: "require_approval",
  title: "Helm uninstall / rollback / forced upgrade",
  description:
    'Removes or rewinds a Helm release, or forces an upgrade past Helm\'s own safety checks — all of which change what is running in a cluster. Does NOT match the idempotent deploy everyone actually uses (`helm upgrade --install`), nor `helm list`, `helm template` or `helm diff`. Like every rule in this pack it cannot see which cluster is selected, so it treats a local kind cluster and production identically. Global flags between `helm` and its subcommand are tolerated (`helm -n <ns> uninstall …`, `--kube-context <ctx>`), and an absolute tool path still matches; a flag that itself runs a program is not read. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\bhelm${LEADING_FLAGS}\\s+(uninstall|delete)\\b`,
          `\\bhelm${LEADING_FLAGS}\\s+rollback\\b`,
          `\\bhelm${LEADING_FLAGS}\\s+upgrade\\b[^|;&]*--force\\b`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("helm uninstall api"),
      bash("helm rollback api 3"),
      bash("helm upgrade api ./chart --force"),
      bash("helm -n prod uninstall api"),
      bash("helm --kube-context prod-eu rollback api 3"),
    ],
    allow: [
      ...mentions("helm uninstall api"),
      bash("helm upgrade --install api ./chart"),
      bash("helm list -A"),
      bash("helm template ./chart"),
      bash("helm diff upgrade api ./chart"),
    ],
  },
};
