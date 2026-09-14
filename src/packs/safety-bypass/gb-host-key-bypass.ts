// cspell:words stricthostkeychecking userknownhostsfile

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Accepting any SSH host key. The check exists to notice exactly one thing — that
 * the machine you reached is the machine you meant — and these flags are how it
 * stops noticing.
 */
export const gbHostKeyBypass: Rule = {
  id: "gb.host-key-bypass",
  category: "safety-bypass",
  severity: "high",
  defaultAction: "require_approval",
  title: "Accepting any SSH host key",
  description:
    'Holds `StrictHostKeyChecking=no`, a `UserKnownHostsFile` pointed at /dev/null, or a blind `ssh-keyscan` appended to known_hosts. Host-key checking exists to notice one thing — that the machine you reached is the machine you meant — and each of these is how it stops noticing. Does NOT match ordinary ssh, git-over-ssh or key generation. It cannot tell a CI runner (where this is sometimes the pragmatic answer) from a developer laptop, because no environment reaches the guard. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "stricthostkeychecking[= ]\\s*no\\b",
          "userknownhostsfile[= ]\\s*/dev/null",
          "\\bssh-keyscan\\b[^|;&]*>>\\s*[^|;&]*known_hosts",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("ssh -o StrictHostKeyChecking=no deploy@example.com"),
      bash("ssh -o UserKnownHostsFile=/dev/null deploy@example.com"),
      bash("ssh-keyscan example.com >> ~/.ssh/known_hosts"),
    ],
    allow: [
      ...mentions("ssh -o StrictHostKeyChecking=no deploy@example.com"),
      bash("ssh -T git@github.com"),
      bash("ssh-keygen -t ed25519 -C dev@example.com"),
      bash("git clone git@github.com:o/r.git"),
      bash("cat ~/.ssh/known_hosts | wc -l"),
    ],
  },
};
