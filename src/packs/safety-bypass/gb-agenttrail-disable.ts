// cspell:words disableallhooks argjson

import { QUOTED_MENTION, SEP, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The agent switching off the guard that watches it, from the shell.
 *
 * File tools on the guard's own config are held by `fs.agent-self-config`. This holds
 * the commands that do the same job without a file tool: the guard CLI loosening a
 * guardrail or removing itself, removing the plugin or the package, signing the platform
 * CLI out, dropping the enforcement sentinel, and the Claude Code switches that turn
 * every hook off or point a nested session at other settings.
 *
 * Held rather than blocked: a person sometimes means to do exactly this, and approving
 * it is the right way for them to say so.
 */
export const gbAgenttrailDisable: Rule = {
  id: "gb.agenttrail-disable",
  category: "safety-bypass",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI09", "ASI10"],
  title: "Disabling or removing AgentTrail from the shell",
  description:
    "Holds a shell command that loosens or removes the guard that watches the agent. Catches: the guard CLI (`agenttrail-guard`, `npx @agenttrail/guard`, `pnpm dlx`, or a global or repository build of its `cli.js`) running `guardrails`/`rules` `disable`, `set-action`, `allow`, `reset`, `remove` or `fail-mode`, or `uninstall`; `claude plugin disable|uninstall|remove` or `claude plugin marketplace remove` on an AgentTrail plugin; `npm`, `pnpm`, `yarn` or `bun` removing an `@agenttrail/` package; `agenttrail logout`, also through `npx @agenttrail/cli` and after global flags; unsetting `AGENTTRAIL_PEP_ENFORCE` or setting it to anything but `1`, which the guard reads as off (`unset`, `env -u`, `=`, `=0`, `=no`, `del(…)` in jq, PowerShell `Remove-Item env:`); setting `disableAllHooks` to `true` (`jq '.disableAllHooks=true'` or `|= true`, `claude config set -g disableAllHooks true`, `--settings '{\"disableAllHooks\":true}'`); `claude config set|add|remove|reset` on hooks, env or permissions; and a nested `claude` run with `--settings` or `CLAUDE_CONFIG_DIR`. Not held: reading (`list`, `show`, `status`, `jq .disableAllHooks …`), `enable`, `init`, installing, or `agenttrail login`. Held, not blocked, because a person sometimes means to do this. Reading the value (`[ \"$AGENTTRAIL_PEP_ENFORCE\" = 1 ]`) is not held. Known misses: a command word broken with quotes or backslashes (`agenttrail-gu''ard`), a subcommand spelled the same way, other jq spellings of `disableAllHooks` (`//= true`, `= (true)`, `--argjson v true`), a command run from a script file, and an encoded command. The strong protection is deploying the hooks through managed settings. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          // The guard CLI loosening a guardrail or removing itself.
          `(?:agenttrail-guard|@agenttrail/guard(?:@\\S{0,40})?|guard[/\\\\](?:dist|src)[/\\\\]cli\\.[cm]?[jt]s)\\b[^|;&\\n]{0,200}${SEP}["']?(?:(?:guardrails|rules)["']?(?:${SEP}{1,4}-\\S{1,30}){0,3}${SEP}{1,4}["']?(?:disable|set-action|allow|reset|remove|fail-mode)|uninstall)\\b`,
          // Claude Code's plugin commands on an AgentTrail plugin or marketplace.
          `\\bclaude\\b[^|;&\\n]{0,100}${SEP}plugins?${SEP}{1,4}(?:marketplace${SEP}{1,4})?(?:disable|uninstall|remove|rm)\\b[^|;&\\n]{0,200}agenttrail`,
          // A package manager removing an @agenttrail package.
          `\\b(?:npm|pnpm|yarn|bun)\\b[^|;&\\n]{0,100}${SEP}(?:uninstall|un|remove|rm|r|unlink)\\b[^|;&\\n]{0,200}@agenttrail/`,
          // The platform CLI signing out, after up to four global flags.
          `(?:^|[^\\w./-])(?:agenttrail|@agenttrail/cli(?:@\\S{0,40})?)["']?(?:${SEP}{1,4}-\\S{1,60}(?:${SEP}{1,4}[^-\\s]\\S{0,100})?){0,4}${SEP}{1,4}logout\\b`,
          // The enforcement sentinel removed.
          `\\bunset${SEP}[^|;&\\n]{0,100}\\bagenttrail_pep_enforce\\b|\\benv\\b[^|;&\\n]{0,100}(?:-u${SEP}{0,4}|--unset[=\\s])agenttrail_pep_enforce`,
          // Set, not read: no `$` or `${` before the name, and any value but 1 (jq's `|=` too).
          `(?:^|[^$\\w{])agenttrail_pep_enforce["']?\\s{0,4}\\|?=(?!=|["']?1["']?(?:${SEP}|$|[;&|)']))|del\\([^)]{0,100}agenttrail_pep_enforce|remove-item\\s[^|;&\\n]{0,40}env:agenttrail_pep_enforce`,
          // Claude Code's switch that turns every hook off.
          `\\bdisableallhooks["']?\\s{0,4}(?:\\|?[:=]|${SEP}{1,4})\\s{0,4}["']?true\\b`,
          // Claude Code's own config, and a nested session on other settings.
          `\\bclaude\\b[^|;&\\n]{0,100}${SEP}config${SEP}{1,4}(?:set|add|remove|reset)\\b[^|;&\\n]{0,200}(?:hooks|disableallhooks|env|permissions)`,
          `\\bclaude\\b[^|;&\\n]{0,200}${SEP}--settings\\b|\\bclaude_config_dir["']?\\s{0,4}=`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("agenttrail-guard guardrails disable dd.rm-rf-absolute"),
      bash("agenttrail-guard guardrails set-action dd.rm-rf-absolute warn"),
      bash('agenttrail-guard rules allow dd.rm-rf-absolute "rm -rf /x"'),
      bash("agenttrail-guard guardrails reset --all"),
      bash("agenttrail-guard guardrails remove my-rule"),
      bash("agenttrail-guard guardrails fail-mode open"),
      bash("agenttrail-guard uninstall --agent claude"),
      bash("agenttrail-guard --json guardrails 'disable' destructive-data"),
      bash("npx @agenttrail/guard guardrails disable destructive-data"),
      bash("npx -y @agenttrail/guard@latest uninstall"),
      bash("pnpm dlx @agenttrail/guard guardrails disable destructive-data"),
      bash("node tools/guard/dist/cli.js guardrails set-action dd.rm-rf-absolute warn"),
      bash("node ~/.npm/lib/node_modules/@agenttrail/guard/dist/cli.js uninstall"),
      bash("claude plugin disable agenttrail-guard"),
      bash("claude plugin uninstall agenttrail-guard@agenttrail"),
      bash("claude plugin marketplace remove agenttrail"),
      bash("npm uninstall -g @agenttrail/guard"),
      bash("npm rm -g @agenttrail/cli"),
      bash("pnpm remove -g @agenttrail/cli"),
      bash("agenttrail logout"),
      bash("npx @agenttrail/cli@latest logout"),
      bash("agenttrail --endpoint https://api.example.com logout"),
      bash("unset AGENTTRAIL_PEP_ENFORCE"),
      bash("env -u AGENTTRAIL_PEP_ENFORCE claude -p hi"),
      bash("AGENTTRAIL_PEP_ENFORCE= claude -p hi"),
      // The guard enforces only when the value is exactly 1, so any other value turns it off.
      bash("export AGENTTRAIL_PEP_ENFORCE=no"),
      bash("AGENTTRAIL_PEP_ENFORCE=2 claude -p hi"),
      bash("AGENTTRAIL_PEP_ENFORCE=true claude -p hi"),
      bash("jq '.env.AGENTTRAIL_PEP_ENFORCE |= \"0\"' settings.json"),
      bash("jq 'del(.env.AGENTTRAIL_PEP_ENFORCE)' settings.json"),
      pwsh("Remove-Item env:AGENTTRAIL_PEP_ENFORCE"),
      bash("claude config set -g disableAllHooks true"),
      bash("jq '.disableAllHooks=true' settings.json"),
      bash("jq '.disableAllHooks |= true' settings.json"),
      bash("claude --settings '{\"disableAllHooks\":true}' -p hi"),
      bash("claude config set hooks '{}'"),
      bash("CLAUDE_CONFIG_DIR=/tmp/cfg claude -p hi"),
      mcp({ command: "agenttrail-guard guardrails disable destructive-data" }),
    ],
    allow: [
      ...mentions("agenttrail-guard guardrails disable dd.rm-rf-absolute"),
      bash("agenttrail-guard guardrails list"),
      bash("agenttrail-guard guardrails show dd.rm-rf-absolute"),
      bash("agenttrail-guard guardrails enable dd.rm-rf-absolute"),
      bash("agenttrail-guard status"),
      bash("agenttrail-guard init --agent claude"),
      bash("npm install -g @agenttrail/guard"),
      bash("claude plugin install agenttrail-guard@agenttrail"),
      bash("claude plugin disable some-other-plugin"),
      bash("agenttrail login"),
      bash("agenttrail status"),
      bash("jq .disableAllHooks ~/.claude/settings.json"),
      bash("claude config set theme dark"),
      bash("export AGENTTRAIL_PEP_ENFORCE=1"),
      bash('export AGENTTRAIL_PEP_ENFORCE="1"'),
      bash("AGENTTRAIL_PEP_ENFORCE=1; claude -p hi"),
      bash('[ "$AGENTTRAIL_PEP_ENFORCE" == "1" ] && echo on'),
      // Reading the value in a test, and turning it on with jq.
      bash('[ "$AGENTTRAIL_PEP_ENFORCE" = "1" ] && echo on'),
      bash('test "$AGENTTRAIL_PEP_ENFORCE" = 1'),
      bash(`test "\${AGENTTRAIL_PEP_ENFORCE}" = 0 && echo off`),
      bash("jq '.env.AGENTTRAIL_PEP_ENFORCE=\"1\"' settings.json"),
    ],
  },
};
