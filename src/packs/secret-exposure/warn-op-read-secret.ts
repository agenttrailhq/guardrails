import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

export const warnOpReadSecret: Rule = {
  id: "warn-op-read-secret",
  category: "secret-exposure",
  severity: "info",
  defaultAction: "warn",
  title: "Flag `op read` secret access",
  description:
    'Surfaces a secret read through the 1Password CLI (op read, op item get, op document get, op inject) so secret access gets a second look without breaking routine dev flow. Severity is `info` rather than `low` deliberately: it is warn-only over one narrow path, and `low` would overstate it. The words are matched on WORD BOUNDARIES, so a commit message containing `stop reading from cache` no longer trips it. MISSES secrets read via another CLI (aws, vault, gcloud — see se.secret-manager-read), a .env opened by a file tool, and an `op` wrapper script whose own text does not name the subcommand. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: ["\\bop\\s+(read|item\\s+get|document\\s+get|inject)\\b"],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("op read 'op://vault/db/password'"),
      bash("op item get db --fields password"),
      bash("op inject -i .env.tpl -o .env"),
    ],
    allow: [
      ...mentions("op read op://vault/db/password"),
      bash('git commit -m "stop reading from cache"'),
      bash("op signin"),
      bash("op vault list"),
      bash("cargo build --workspace"),
    ],
  },
};
