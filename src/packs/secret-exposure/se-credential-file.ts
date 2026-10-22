// cspell:words apiserver configmap extglob extraheader gshadow keytabs kubeconfig nmconnection pypirc rancher sudoers tfstate tfvars
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The file-channel half of this pack: the paths where a credential actually
 * lives on disk. Filed here BY HARM rather than in `file-scope` — what it
 * protects is the secret inside the file, not the fact that a path was touched.
 *
 * `.pub` is excluded because a public key is public; that exclusion is also the
 * reason `**​/.ssh/id_*` is safe to write as a wildcard.
 *
 * ── Reads of files whose edit is held by another guardrail ───────────────────
 *
 * Several files hold a secret but are filed elsewhere by their EDIT harm: system files
 * (`fs.system-paths`), git's internals (`fs.vcs-internals`), the agent's own configuration
 * (`fs.agent-self-config`, `ac.mcp-server-add`) and production configuration
 * (`block-prod-config-edit`). Those guardrails exclude the `Read` and `Grep` tools, because
 * looking at a CI definition or a settings file is routine. For the files below the read is
 * the harm, so this guardrail holds it. Each of those arms is scoped to `{Read,Grep}`: an edit
 * is already held by the guardrail that owns the path, and matching it here too would add
 * nothing.
 *
 * One arm is scoped to `Grep` alone: a search anywhere under `/etc`. A Grep's target is
 * whatever folder or wildcard the agent passes (`/etc`, `/etc/ssh` with `*_key`), so naming
 * files cannot catch a search that prints a key or a password hash. Reading one named,
 * non-secret file such as `/etc/hosts` stays allowed.
 *
 * The production arms are narrower than `block-prod-config-edit`'s patterns, because an agent
 * reads far more often than it edits: they hold only configuration and secret file types
 * (`PROD_CONFIG`), and they skip anything under a `node_modules`, `dist` or `vendor` folder
 * (`NOT_VENDORED`), where `react.production.min.js` and its kin live. Both limits are written
 * into each production arm rather than into a `none_of`, because a `none_of` applies to the
 * whole guardrail and would also release, say, a `.pem` under `vendor/` from the arm above.
 */

/**
 * Zero or more folders, none of them named exactly `node_modules`, `dist` or `vendor`, anywhere
 * in the path, an absolute path's leading folders included.
 *
 * Each folder matches one of two alternatives. `!(node_modules|dist|vendor)` alone is not
 * enough: picomatch compiles it as "does not START with one of these", so it would also refuse
 * `distribution/`, `vendors/` and `dist-config/`. The second alternative, a reserved name
 * followed by at least one more character, lets those through again, so only the exact names
 * are skipped.
 */
const NOT_VENDORED = "*(@(!(node_modules|dist|vendor)|@(node_modules|dist|vendor)[^/]*)/)";

/** The file types a production configuration or secret is written in. */
const PROD_CONFIG = "@(yml|yaml|json|toml|env|ini|conf|properties|tf|tfvars)";

export const seCredentialFile: Rule = {
  id: "se.credential-file",
  category: "secret-exposure",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "ASI03", "LLM02"],
  title: "Opening a file that holds credentials",
  description:
    "Holds a file tool opening a path where credentials live — an SSH private key, an AWS credentials file, a PEM/P12/PFX/JKS keystore, `.npmrc` or `.pypirc` (which hold registry tokens), a Docker config, or a kubeconfig. Public keys are excluded (`*.pub`). It matches the PATH ONLY: it cannot tell whether the file actually holds a secret, so a `.pem` that is a public certificate is held too, and a credential in a file named something else is missed entirely. `.env` files are covered separately by block-env-file-read. " +
    "It also holds READING — the `Read` and `Grep` tools, nothing else — of files whose edit another guardrail already holds and which commonly carry a secret: `/etc/shadow`, `/etc/gshadow`, their `-` backups, `/etc/sudoers` and `/etc/sudoers.d/`; SSH host private keys (`/etc/ssh/ssh_host_*_key` and the legacy `/etc/ssh/ssh_host_key`); `/etc/ssl/private/` and `/etc/pki/tls/private/`; Kubernetes admin configs (`/etc/kubernetes/*.conf`) and private keys (`/etc/kubernetes/pki/**/*.key`); the k3s kubeconfig (`/etc/rancher/k3s/k3s.yaml`); a repository's `.git/config`, where a remote URL or extra header can carry a token; agent configuration that often holds API keys — `.mcp.json`, `.claude/settings.local.json`, `.claude.json`, `.cursor/mcp.json` and `.codex/config.toml`; and production configuration: a `.yml`, `.yaml`, `.json`, `.toml`, `.env`, `.ini`, `.conf`, `.properties`, `.tf` or `.tfvars` file named `*.prod.*`, `prod.*`, `*.production.*` or `production.*`, or under a `prod/` or `production/` folder, unless any folder in the path, an absolute path's leading folders included, is named exactly `node_modules`, `dist` or `vendor` (so `/srv/vendor/app/config/database.prod.yml` is not held). A Grep anywhere under `/etc`, including a search of the folder itself or with a wildcard, is held too; a Read of an `/etc` file not named here is not. Editing those files is held by the guardrail that owns the path, not by this one. " +
    "NOT held on read by this guardrail: a shell command such as `cat`, on any agent (Codex has no read tool, so its reads are always shell commands); a file tool other than Read and Grep, such as Claude Code's Glob or another Cursor tool, which the guardrail that owns the path still holds under its own title, except on `.claude.json`, which no other guardrail names; `.claude/settings.json`, at project or user level; other secrets under `/etc` such as Kerberos keytabs and VPN or Wi-Fi connection files, which are held on Grep only; a Grep of a production folder with no file pattern, or with a pattern whose extension is a wildcard; production files of other types, such as `.key`, `.tfstate`, `.hcl`, `.cfg`, `.xml`, `.config` or Angular's `environment.prod.ts`; and production code or prose, such as `webpack.prod.js` or a runbook in `docs/production/`.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.ssh/id_*" },
      { kind: "execute_tool", file_glob: "**/id_rsa" },
      { kind: "execute_tool", file_glob: "**/id_ed25519" },
      { kind: "execute_tool", file_glob: "**/.aws/credentials" },
      { kind: "execute_tool", file_glob: "**/*.pem" },
      { kind: "execute_tool", file_glob: "**/*.{p12,pfx,jks,keystore}" },
      { kind: "execute_tool", file_glob: "**/.npmrc" },
      { kind: "execute_tool", file_glob: "**/.pypirc" },
      { kind: "execute_tool", file_glob: "**/.docker/config.json" },
      { kind: "execute_tool", file_glob: "**/.kube/config" },
      // Read only (see the header): system account and privilege files, host and TLS keys,
      // cluster admin configs and keys.
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: "/etc/{shadow,shadow-,gshadow,gshadow-,sudoers}",
      },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/sudoers.d/**" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/ssh/ssh_host_*_key" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/ssh/ssh_host_key" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/ssl/private/**" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/pki/tls/private/**" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/kubernetes/*.conf" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/kubernetes/pki/**/*.key" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "/etc/rancher/k3s/k3s.yaml" },
      // Grep only: a search anywhere under `/etc`, including the folder itself.
      { kind: "execute_tool", label: "Grep", file_glob: "/etc/**" },
      // Read only: a remote URL or `http.extraheader` can carry a token.
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.git/config" },
      // Read only: MCP server definitions and agent settings often carry API keys in `env`.
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.mcp.json" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.claude/settings.local.json" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.claude.json" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.cursor/mcp.json" },
      { kind: "execute_tool", label: "{Read,Grep}", file_glob: "**/.codex/config.toml" },
      // Read only: production configuration and secret files (see the header).
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}*.prod.?(*.)${PROD_CONFIG}`,
      },
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}prod.?(*.)${PROD_CONFIG}`,
      },
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}*.production.?(*.)${PROD_CONFIG}`,
      },
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}production.?(*.)${PROD_CONFIG}`,
      },
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}prod/${NOT_VENDORED}*.${PROD_CONFIG}`,
      },
      {
        kind: "execute_tool",
        label: "{Read,Grep}",
        file_glob: `${NOT_VENDORED}production/${NOT_VENDORED}*.${PROD_CONFIG}`,
      },
    ],
    none_of: [{ kind: "execute_tool", file_glob: "**/*.pub" }],
  },
  fixtures: {
    block: [
      file("/home/dev/.ssh/id_rsa", "Read"),
      file("/Users/dev/.aws/credentials", "Read"),
      file("certs/server.pem", "Read"),
      file(".npmrc", "Write"),
      // The other arms hold every tool, under a production or vendored path too: the
      // production arms' limits do not reach them.
      file("/home/prod/.ssh/id_rsa.txt", "Edit"),
      file("/home/prod/.ssh/id_rsa.txt", "Read"),
      file("/srv/production/.ssh/id_ed25519.md", "Write"),
      file("vendor/certs/server.pem", "Read"),
      // The original arms, each with a path only that arm matches.
      file("/home/dev/keys/id_rsa", "Read"),
      file("backup/id_ed25519", "Write"),
      file("certs/client.p12", "Read"),
      file("android/app/release.jks", "Edit"),
      file("/home/dev/.pypirc", "Read"),
      file("/home/dev/.docker/config.json", "Read"),
      file("/home/dev/.kube/config", "Grep"),
      // Each read-only arm, once through Read and once through Grep.
      file("/etc/shadow", "Read"),
      file("/etc/gshadow", "Grep"),
      file("/etc/sudoers", "Read"),
      file("/etc/shadow-", "Read"),
      file("/etc/gshadow-", "Read"),
      file("/etc/sudoers.d/90-cloud-init-users", "Read"),
      file("/etc/sudoers.d/admins", "Grep"),
      file("/etc/ssh/ssh_host_ed25519_key", "Read"),
      file("/etc/ssh/ssh_host_rsa_key", "Grep"),
      file("/etc/ssh/ssh_host_key", "Read"),
      file("/etc/ssh/ssh_host_key", "Grep"),
      file("/etc/ssl/private/server.key", "Read"),
      file("/etc/ssl/private/ca.key", "Grep"),
      file("/etc/pki/tls/private/server.key", "Read"),
      file("/etc/pki/tls/private/localhost.key", "Grep"),
      file("/etc/kubernetes/admin.conf", "Read"),
      file("/etc/kubernetes/controller-manager.conf", "Grep"),
      file("/etc/kubernetes/pki/ca.key", "Read"),
      file("/etc/kubernetes/pki/etcd/ca.key", "Grep"),
      file("/etc/rancher/k3s/k3s.yaml", "Read"),
      file("/etc/rancher/k3s/k3s.yaml", "Grep"),
      // The Grep-only arm: a folder, a wildcard joined to a folder, and the root of `/etc`.
      file("/etc", "Grep"),
      file("/etc/ssh", "Grep"),
      file("/etc/kubernetes", "Grep"),
      file("/etc/ssh/*_key", "Grep"),
      file("/etc/shadow*", "Grep"),
      file("/etc/hosts", "Grep"),
      file("/repo/.git/config", "Read"),
      file("/repo/.git/config", "Grep"),
      file(".mcp.json", "Read"),
      file(".mcp.json", "Grep"),
      file("/repo/.claude/settings.local.json", "Read"),
      file("/repo/.claude/settings.local.json", "Grep"),
      file("/Users/dev/.claude.json", "Read"),
      file("/Users/dev/.claude.json", "Grep"),
      file("/repo/.cursor/mcp.json", "Read"),
      file("/Users/dev/.cursor/mcp.json", "Grep"),
      file("/Users/dev/.codex/config.toml", "Read"),
      file("/Users/dev/.codex/config.toml", "Grep"),
      file("config/database.prod.yml", "Read"),
      file("docker-compose.prod.yml", "Grep"),
      file("config/prod.json", "Read"),
      file("config/prod.env", "Grep"),
      file("config/app.production.json", "Read"),
      file("config/app.production.toml", "Grep"),
      file("config/production.yaml", "Read"),
      file("config/production.env", "Grep"),
      file("deploy/prod/values.yaml", "Read"),
      file("infra/envs/prod/main.tfvars", "Grep"),
      file("deploy/prod/app.properties", "Read"),
      file("k8s/production/secrets.yaml", "Read"),
      file("k8s/production/configmap.yml", "Grep"),
      // Folders that only start with a skipped name are still held.
      file("distribution/prod.json", "Read"),
      file("vendors/config/production.yml", "Grep"),
      // One fixture per file type not used above.
      file("infra/prod/main.tf", "Read"),
      file("config/nginx.prod.conf", "Read"),
      file("config/app.prod.ini", "Grep"),
    ],
    allow: [
      file("/home/dev/.ssh/id_rsa.pub", "Read"),
      file("certs/server.crt", "Read"),
      file("src/index.ts"),
      file("package.json"),
      // Near-misses of the read-only arms.
      file("/etc/passwd", "Read"),
      file("/etc/passwd-", "Read"),
      file("/etc/group", "Read"),
      file("/etc/hosts", "Read"),
      file("/etc/sudo.conf", "Read"),
      file("/etc/ssh/ssh_host_ed25519_key.pub", "Read"),
      file("/etc/ssh/ssh_host_key.pub", "Read"),
      file("/etc/ssh/sshd_config", "Read"),
      file("/etc/ssl/certs/ca-certificates.crt", "Read"),
      file("/etc/pki/tls/certs/server.crt", "Read"),
      file("/etc/kubernetes/manifests/kube-apiserver.yaml", "Read"),
      file("/etc/kubernetes/pki/ca.crt", "Read"),
      file("/etc/rancher/k3s/config.yaml", "Read"),
      file("/opt/etc/app.conf", "Grep"),
      file("/repo/.git/HEAD", "Read"),
      file("/repo/.gitconfig.example", "Read"),
      file("mcp.json.example", "Read"),
      file("/repo/.claude/settings.json", "Read"),
      file("/repo/claude.json", "Read"),
      file("/repo/.cursor/rules/style.mdc", "Read"),
      file("/repo/codex/config.toml", "Read"),
      file("config/database.staging.yml", "Read"),
      // Production code, prose and vendored files are not production configuration.
      file("node_modules/react/cjs/react.production.min.js", "Read"),
      file("node_modules/react-router/dist/production/index.d.ts", "Grep"),
      // One vendored configuration file per production arm.
      file("node_modules/some-lib/config/app.prod.json", "Read"),
      file("dist/prod.json", "Read"),
      file("node_modules/some-lib/config/app.production.json", "Grep"),
      file("vendor/config/production.yml", "Read"),
      file("dist/prod/app.json", "Read"),
      file("vendor/production/config.yml", "Grep"),
      file("src/Settings.prod.test.tsx", "Read"),
      file("infra/bin/prod.ts", "Read"),
      file("webpack.prod.js", "Grep"),
      file("config/database.prod.md", "Read"),
      file("config/prod.md", "Read"),
      file("config/app.production.mdx", "Read"),
      file("config/production.txt", "Read"),
      file("deploy/prod/RUNBOOK.txt", "Grep"),
      file("docs/production/README.md", "Read"),
      // The read-only arms do not hold an edit: the guardrail that owns each path does.
      file("/etc/shadow", "Edit"),
      file("/etc/shadow-", "Write"),
      file("/etc/sudoers.d/admins", "Write"),
      file("/etc/ssh/ssh_host_ed25519_key", "Write"),
      file("/etc/ssh/ssh_host_key", "Edit"),
      file("/etc/ssl/private/server.key", "Edit"),
      file("/etc/pki/tls/private/server.key", "Write"),
      file("/etc/kubernetes/admin.conf", "Write"),
      file("/etc/kubernetes/pki/sa.key", "Write"),
      file("/etc/rancher/k3s/k3s.yaml", "Edit"),
      file("/etc/hosts", "Edit"),
      file("/repo/.git/config", "Edit"),
      file(".mcp.json", "Edit"),
      file("/repo/.claude/settings.local.json", "Write"),
      file("/Users/dev/.claude.json", "Write"),
      file("/repo/.cursor/mcp.json", "Edit"),
      file("/Users/dev/.codex/config.toml", "Edit"),
      file("config/database.prod.yml", "Edit"),
      file("config/prod.json", "Write"),
      file("config/app.production.json", "Edit"),
      file("config/production.yaml", "Write"),
      file("deploy/prod/values.yaml", "Edit"),
      file("k8s/production/secrets.yaml", "Write"),
    ],
  },
};
