// cspell:words cloudflared exfiltration frpc localtunnel pinggy serveo tailnet
import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Exposing a local service to the public internet through a tunnel.
 *
 * A tunnel puts something that was only reachable on the machine — a dev server, a database, the
 * whole loopback interface — on a public URL, past every firewall. It is a legitimate demo tool
 * and a standard exfiltration and inbound-access channel, which is why this asks rather than blocks.
 */
export const exTunnelExpose: Rule = {
  id: "ex.tunnel-expose",
  category: "exfiltration",
  severity: "high",
  defaultAction: "require_approval",
  title: "Exposing a local port through a public tunnel",
  description:
    'Holds a command that puts a local service on a public URL through a tunnel: `ngrok http|tcp|start`, `cloudflared tunnel`, `localtunnel` / `lt --port`, `tailscale funnel`, an `ssh -R` remote forward (including `-NR`), the `serveo.net` and `localhost.run` SSH relays, `bore local`, `frpc`, and `pinggy.io`. Each reaches past the firewall and gives the outside world a route in, which is a demo convenience and an exfiltration channel both. Deliberately NOT matched: `ssh -L` (a local forward, inbound to you) and `ssh -D` (a SOCKS proxy), `ngrok config check` / `--version`, `cloudflared --version`, and `tailscale status` / `serve` (which stays inside the tailnet). MISSES a tunnel binary run under another name, a raw `ssh -R` to a private relay this list does not name, and `frp` driven from its config file rather than the `frpc` command. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bngrok\\s+(?:http|tcp|start)\\b",
          "\\bcloudflared\\s+tunnel\\b",
          "\\b(?:localtunnel\\s+--port|lt\\s+--port|npx\\s+(?:--yes\\s+)?localtunnel)\\b",
          "\\btailscale\\s+funnel\\b",
          "\\bssh\\b[^|;&]*\\s-[A-Za-z]*R(?![A-Za-z])",
          "\\b(?:serveo\\.net|localhost\\.run)\\b",
          "\\bbore\\s+local\\b",
          "\\bfrpc\\b",
          "\\bpinggy\\.io\\b",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("ngrok http 3000"),
      bash("ngrok tcp 22"),
      bash("cloudflared tunnel --url http://localhost:8080"),
      bash("lt --port 8000"),
      bash("npx --yes localtunnel --port 3000"),
      bash("tailscale funnel 3000"),
      bash("ssh -R 80:localhost:3000 nokey@localhost.run"),
      bash("ssh -fNR 8080:localhost:8080 user@vps.example"),
      bash("ssh -R 80:localhost:3000 serveo.net"),
      bash("bore local 8000 --to bore.pub"),
      bash("frpc -c ./frpc.toml"),
      pwsh("ngrok http 5000"),
    ],
    allow: [
      ...mentions("ngrok http 3000"),
      bash("ssh -L 8080:localhost:80 bastion.example"),
      bash("ssh -D 1080 bastion.example"),
      bash("ngrok config check"),
      bash("ngrok --version"),
      bash("cloudflared --version"),
      bash("tailscale status"),
      bash("git clone https://github.com/ekzhang/bore"),
      bash("ssh deploy@host 'systemctl restart api'"),
    ],
  },
};
