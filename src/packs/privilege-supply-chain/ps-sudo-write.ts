import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `sudo` used to WRITE, rather than to read or query. The distinction is the
 * whole rule: `sudo apt-get update` and `sudo systemctl status` are ordinary,
 * while `sudo tee /etc/hosts` and `sudo sh -c` change the machine.
 */
export const psSudoWrite: Rule = {
  id: "ps.sudo-write",
  category: "privilege-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "sudo used to write or to run a shell",
  description:
    'Holds a `sudo` that writes or spawns a shell — `sudo tee`, `sudo dd`, `sudo cp/mv/rm/ln/install`, `sudo chown`, `sudo sh -c` — as opposed to a `sudo` that reads or queries. The read/query forms are deliberately NOT matched: `sudo apt-get update`, `sudo -l` and `sudo systemctl status` are ordinary. It reads the command\'s own words, so it MISSES a write performed by a script invoked with sudo, and it cannot tell which path is being written to. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          "\\bsudo\\s+(tee|dd)\\b",
          "\\bsudo\\s+(cp|mv|rm|ln|install|chown|chmod)\\b",
          "\\bsudo\\s+(ba|z|k|da)?sh\\b",
          "\\|\\s*sudo\\s+tee\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("echo '127.0.0.1 x' | sudo tee -a /etc/hosts"),
      bash("sudo cp dist/app /usr/local/bin/app"),
      bash("sudo rm -rf /var/lib/app"),
      bash('sudo sh -c "echo x > /etc/motd"'),
      mcp({ command: "sudo cp dist/app /usr/local/bin/app" }),
    ],
    allow: [
      ...mentions("echo 127.0.0.1 x | sudo tee -a /etc/hosts"),
      bash("sudo apt-get update"),
      bash("sudo -l"),
      bash("sudo systemctl status nginx"),
      bash("cp dist/app ./bin/app"),
    ],
  },
};
