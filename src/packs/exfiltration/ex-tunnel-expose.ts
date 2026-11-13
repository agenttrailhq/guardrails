// cspell:words AUTHTOKEN cloudflared exfiltration frpc localtunnel nohup pinggy serveo tailnet
import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * A command position: where a shell starts running a word as a program.
 *
 * The start of the text, a new line, or a command separator (`;`, `&`, `|`, `(`, a backtick),
 * or the opening quote of a `-c` string (`bash -c "…"`) or of a JSON string value (an MCP shell
 * tool's `{"command":"…"}`); then up to four wrapper words that run
 * the next word as a program (`sudo`, `nohup`, `exec`, `time`, `command`, `env`, `npx`,
 * `pnpm dlx`, `timeout <n>`) or `NAME=value` assignments; then an optional directory prefix
 * (`/usr/local/bin/`). A tunnel tool named anywhere else — inside a PR body, a heredoc, a note
 * written to a file — is text, not a run.
 */
const RUNS =
  '(?:^|[\\n;&|(`]|-c\\s+["\']|:\\s*")\\s*(?:(?:sudo|nohup|exec|time|command|env|npx|pnpm\\s+dlx|timeout\\s+\\S{1,20}|\\w{1,40}=\\S{0,200})\\s+){0,4}(?:[^\\s;&|(`"\']{0,200}/)?';

/** An `ssh` command, then its arguments up to the next separator or quote. */
const SSH = "(?:^|[\\s;&|(/])ssh(?=\\s)[^|;&\"'<>]*";

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
  owasp: ["ASI02", "ASI03", "LLM02"],
  title: "Exposing a local port through a public tunnel",
  description:
    'Holds a command that puts a local service on a public URL through a tunnel: `ngrok http|tcp|start`, `cloudflared tunnel`, `localtunnel` / `lt --port`, `tailscale funnel`, an `ssh -R` remote forward (including `-NR`, matched only when `ssh` is the command being run), the `serveo.net` and `localhost.run` SSH relays, `bore local`, `frpc` invoked with a flag (`frpc -c …`), and the `pinggy.io` relay. A tunnel tool is matched only where a shell would run it: at the start of the command, after a separator (`;`, `&&`, `|`, `(`), inside a `bash -c` string, after a wrapper such as `sudo`, `nohup`, `env NAME=value`, `timeout 600` or `npx`, or by its full path; the three SSH relays only as the target of an `ssh` command. A tunnel tool NAMED in text that is not run — a `gh pr create --body`, a heredoc or a note written to a file — is not held. Each reaches past the firewall and gives the outside world a route in, which is a demo convenience and an exfiltration channel both. Deliberately NOT matched: `ssh -L` (a local forward, inbound to you) and `ssh -D` (a SOCKS proxy), `ngrok config check` / `--version`, `cloudflared --version`, `tailscale status` / `serve` (which stays inside the tailnet), `ssh-keygen -R host` (host-key removal, not a tunnel), a `-R` that appears only inside a quoted remote command (`ssh host "grep -R …"`), and a path or filename that merely contains `frpc` (`scripts/frpc-parser.js`). MISSES a tunnel binary run under another name, or through a wrapper this list does not name (`docker run … ngrok/ngrok http`, `make tunnel`, a shell function or alias), a raw `ssh -R` to a private relay this list does not name, `frp` driven from its config file rather than the `frpc` command, `sudo frpc`, and an `frpc` subcommand invoked without a leading flag. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${RUNS}ngrok\\s+(?:http|tcp|start)\\b`,
          `${RUNS}cloudflared\\s+tunnel\\b`,
          `${RUNS}(?:localtunnel\\s+--port|lt\\s+--port|npx\\s+(?:--yes\\s+)?localtunnel)\\b`,
          `${RUNS}tailscale\\s+funnel\\b`,
          `${SSH}\\s-[A-Za-z]*R(?![A-Za-z])`,
          // The SSH relays are host names, so they count only as the target of an `ssh`.
          `${SSH}\\b(?:serveo\\.net|localhost\\.run|pinggy\\.io)\\b`,
          `${RUNS}bore\\s+local\\b`,
          "(?:^|[;&|(]\\s*|/)frpc\\s+-",
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
      // Run through a wrapper, chained, by path, or inside a `-c` string.
      bash("sudo ngrok http 80"),
      bash("nohup ngrok http 3000 > ngrok.log 2>&1 &"),
      bash("env NGROK_AUTHTOKEN=abc ngrok http 3000"),
      bash("NGROK_AUTHTOKEN=abc ngrok http 3000"),
      bash("pnpm build && ngrok http 4173"),
      bash('bash -c "ngrok http 3000"'),
      bash("/usr/local/bin/cloudflared tunnel run app"),
      bash("timeout 600 bore local 8000 --to bore.pub"),
      bash("npx localtunnel --port 3000"),
      bash("cd web; tailscale funnel 443"),
      bash("ssh -p 443 -R0:localhost:3000 a.pinggy.io"),
      bash("ssh nokey@localhost.run"),
      mcp({ command: "ngrok http 3000" }),
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
      bash("ssh-keygen -R old.example.com"),
      bash('ssh deploy@host "grep -R TODO /srv"'),
      bash("node scripts/frpc-parser.js"),
      bash("cat frpc.toml"),
      // A tunnel tool named in text that is not run.
      bash('gh pr create --title "Docs" --body "Run ngrok http 3000 to share the preview."'),
      bash('gh issue comment 7 --body "tailscale funnel 443 exposes it publicly"'),
      bash(
        "cat > docs/tunnels.md <<'EOF'\nUse cloudflared tunnel --url http://localhost:8080 for demos.\nEOF",
      ),
      bash("printf 'bore local 8000 --to bore.pub\\n' > notes.txt"),
      bash("open https://serveo.net"),
      bash("curl -s https://pinggy.io/docs"),
    ],
  },
};
