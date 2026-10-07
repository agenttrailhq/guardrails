<!-- cspell:words exfiltration kubeconfig hostnames agenttrailhq OWASP slopsquatted -->

<div align="center">

<a href="https://www.agenttrail.sh">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://www.agenttrail.sh/brand/agenttrail_logo_white.svg" />
    <img src="https://www.agenttrail.sh/brand/agenttrail_logo.svg" alt="AgentTrail" width="220" />
  </picture>
</a>

# AgentTrail Guardrails: open-source rules for AI coding agents

**A library of rules for catching dangerous commands before an AI coding agent runs them.**<br />
Plain data you can read, test, and change. Enforced in **Claude Code**, **Cursor**, and **Codex CLI**.

[![CI](https://github.com/agenttrailhq/guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/agenttrailhq/guardrails/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@agenttrail/guardrails?color=0748FE&label=npm)](https://www.npmjs.com/package/@agenttrail/guardrails)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-0748FE)](LICENSE)
[![Node.js 22.13+](https://img.shields.io/badge/node-%3E%3D22.13-0748FE)](https://nodejs.org/)

[Quick start](#quick-start) ·
[The packs](#the-eleven-packs) ·
[OWASP coverage](#owasp-coverage) ·
[Rule format](#a-rule-start-to-finish) ·
[Contribute a rule](#contributing-a-rule) ·
[Changelog](CHANGELOG.md)

</div>

[74 rules](https://www.agenttrail.sh/guardrails), grouped into 11 packs. Apache-2.0. Published
as `@agenttrail/guardrails` and enforced by [AgentTrail Guard](https://github.com/agenttrailhq/guard).

![A Claude Code session: asked to split a name column and push the schema, the agent edits the Prisma schema and seed, then runs npx prisma db push --force-reset to wipe the database. AgentTrail Guard blocks it with the guardrail dd.accept-data-loss, and the agent stops](.github/assets/guard-blocks-force-reset.gif)

<sub>A real Claude Code session. The agent decides to reset the database to get a schema push
through; Guard blocks `prisma db push --force-reset` with `dd.accept-data-loss` before it runs.</sub>

## What this is, in plain terms

Your AI coding agent proposes commands in your terminal all day, and some are ones you would
not have typed yourself: `git reset --hard` over a day's work, `rm -rf` on the wrong path, a
`terraform apply` against production.

This package is the **list of things worth stopping**, written as data. Each entry says what to look
for, how serious it is, and what should happen: allow it, ask a human first, or refuse.

**That is all this package does.** It contains no code that watches your machine and nothing that
talks to the network. Something else has to read the list and act on it: normally
[`agenttrail-guard`](https://github.com/agenttrailhq/guard), which runs on your laptop and checks each
command an agent proposes against these rules.

## Why these rules?

- **Readable.** Every rule is plain data with a title, a severity, a default action, and a
  description that says what it catches **and what it misses**.
- **Proven in both directions.** Every rule ships commands it must catch and near-misses it must
  leave alone, and a shared corpus of everyday commands no rule may match. A rule that fails
  either side does not build.
- **Quiet on purpose.** A commit message or a `grep` that only *mentions* `rm -rf /` is not
  treated as running it. See [Talking about a command is not running it](#talking-about-a-command-is-not-running-it).
- **Mapped to known risks.** The packs line up with the
  [OWASP Top 10s for agentic and LLM applications](#owasp-coverage), and the gaps are stated, not
  hidden.
- **Separate from the enforcer.** You can read, disagree with, and change any rule without
  trusting anything about the tool that enforces it.

## Quick start

**You need:** Node.js 22.13 or newer.

### Enforce the rules in your agent

Most people never install this package directly. [AgentTrail Guard](https://github.com/agenttrailhq/guard)
bundles it, so installing Guard is all it takes:

```bash
npm install -g @agenttrail/guard
agenttrail-guard init --agent claude              # or: --agent cursor, --agent codex
agenttrail-guard guardrails list                  # every rule and its current action
agenttrail-guard guardrails show wt.reset-hard    # one rule in full
agenttrail-guard guardrails set-action <id> warn  # change what a rule does
agenttrail-guard guardrails allow <id> <pattern>  # silence one rule for one command shape
```

See the [AgentTrail Guard README](https://github.com/agenttrailhq/guard#quick-start) for setup
and everything else Guard can do.

### Use the rules in your own code

Install the package if you are writing rules, or building your own tool on top of the list:

```bash
npm install @agenttrail/guardrails
```

```ts
import { RULES, getRule, rulesForPack } from "@agenttrail/guardrails/guardrails";

// Everything that refuses outright, rather than asking or warning.
const blocking = RULES.filter((rule) => rule.defaultAction === "block");
console.log(`${RULES.length} rules, ${blocking.length} block by default`);

// One pack, with each rule's severity and default action.
for (const rule of rulesForPack("secret-exposure")) {
  console.log(rule.id, rule.severity, rule.defaultAction);
}

// One rule, including the limits its description admits to.
console.log(getRule("wt.reset-hard")?.description);
```

This package has no evaluator: it tells you what each rule looks for, not whether a given
command matches. Guard does the matching. [Two ways to import it](#two-ways-to-import-it)
explains the two entry points.

## A rule, start to finish

Here is a complete rule. Nothing is hidden; this is the actual shape.

```jsonc
{
  "id": "wt.reset-hard",
  "category": "working-tree",
  "severity": "high",
  "defaultAction": "block",
  "title": "git reset --hard discards uncommitted work",
  "description": "Discards all uncommitted changes. Does not match `git restore` (see wt.restore-path).",

  // What to look for. This one matches a Bash command against a regular expression.
  "match": {
    "any_of": [
      { "kind": "execute_tool", "label": "Bash", "detail_matches": ["\\bgit\\s+reset\\s+--hard\\b"] }
    ]
  },

  // Proof it works, in both directions (see "Every rule proves both directions" below).
  "fixtures": {
    "block": ["git reset --hard"],
    "allow": ["git reset src/api.ts"]
  }
}
```

The real rule is in [`wt-reset-hard.ts`](src/packs/working-tree/wt-reset-hard.ts); this is a
trimmed copy. With it enforced by Guard, an agent that proposes `git reset --hard` is refused
and told which rule stopped it, while `git reset src/api.ts`, which unstages one file, goes
ahead as normal.

Reading the fields:

| Field | What it means |
|---|---|
| `id` | A stable name. Users type it to disable or change a rule, so it never changes. |
| `severity` | How bad the thing being caught is: `critical`, `high`, `medium`, `low`, `info`. **It is not a price**: this package ships no mapping from severity to money. |
| `defaultAction` | What should happen: `block` (refuse), `require_approval` (ask a human), or `warn` (allow, but say so). A user can override it. |
| `description` | What the rule catches **and what it misses**. The honest limits are part of the rule, not a footnote. |
| `match` | The condition. `any_of` means "any one of these is enough". |
| `fixtures` | Examples that must match, and examples that must not. |

## The eleven packs

A rule is filed by **the harm it prevents**, never by the technique it uses to spot it.

That sounds like a detail and is not. The three rules about production config, `.env` files and API
endpoints all work by matching file paths, but they are *not* in `file-scope`. Someone who turned
that pack off to stop path noise would otherwise silently lose their production and secret
protection, which they never asked to turn off and would not know they had.

| Pack | Rules | What it is about |
|---|---:|---|
| [`working-tree`](src/packs/working-tree/) | 9 | Destroying uncommitted work or published history: `git reset --hard`, `git clean -fd`, force-push, `rm -rf`. |
| [`destructive-data`](src/packs/destructive-data/) | 8 | Data git cannot bring back: a dropped volume, a dropped database, destructive DDL, a deleted shadow copy. |
| [`prod-infra`](src/packs/prod-infra/) | 8 | Changing running infrastructure: Terraform, Kubernetes, Helm, cloud deletes, a deploy that names production. |
| [`secret-exposure`](src/packs/secret-exposure/) | 10 | Credentials and sensitive data leaving where they live. Mostly `warn`: reading a secret is a normal part of a normal day. |
| [`rce-supply-chain`](src/packs/rce-supply-chain/) | 6 | Running code nobody reviewed: pipe-to-shell, a remote runner, a redirected registry, TLS verification off. |
| [`safety-bypass`](src/packs/safety-bypass/) | 7 | Turning off a check somebody installed on purpose, or erasing the record of it: `--no-verify`, `--admin` merge, hooks disabled, host-key checking off, history and log purges, forged terminal output. |
| [`privilege-supply-chain`](src/packs/privilege-supply-chain/) | 6 | Gaining reach or handing it out: `sudo` writes, `chmod 777`, IAM grants, persistence, publishing, new dependencies. |
| [`file-scope`](src/packs/file-scope/) | 4 | The agent wrote somewhere it had no business writing: its own config, the machine, git's internals, the CI definition. |
| [`agent-context`](src/packs/agent-context/) | 6 | The agent changing what it is or what it knows (its standing instructions, its memory, its skills and commands, its MCP servers), or starting more agents, or switching another agent's approvals off. |
| [`test-integrity`](src/packs/test-integrity/) | 6 | The agent making its work look successful: deleting a test, weakening a runner's configuration, accepting every snapshot, switching a coverage gate off, silencing failures in bulk, or telling CI not to run. |
| [`exfiltration`](src/packs/exfiltration/) | 4 | Moving data off the machine or opening a way in: a reverse shell, a public tunnel, a file upload, a paste service. Command channel only. |

Pack names appear in user config files, so renaming one is a breaking change, not a tidy-up.

Each pack name links to its source folder: one TypeScript file per rule, so you can read any rule
end to end. Every rule, with its full description and tested examples, is also in the
[guardrail library](https://www.agenttrail.sh/guardrails) on the AgentTrail website, where you
can paste a command to see which rules match it.

## OWASP coverage

Several packs exist because of risks named in OWASP's two lists for AI systems: the
[Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(ASI01 to ASI10, 2026 edition) and the
[Top 10 for LLM Applications](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
(LLM01 to LLM10, 2026 edition). A rule cannot see a prompt or a model's reasoning, only the
action that comes out of it, so these rules address a risk at the point where it turns into a
command or a file change.

| Pack | Agentic risks | LLM risks | Default action |
|---|---|---|---|
| `working-tree`, `destructive-data`, `prod-infra`, `file-scope` | ASI02 Tool Misuse and Exploitation | LLM03 Excessive Agency | `block` or `require_approval` |
| `rce-supply-chain` | ASI05 Unexpected Code Execution, ASI04 Agentic Supply Chain | LLM04 Supply Chain | `block` or `require_approval` |
| `privilege-supply-chain` | ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain | LLM04 Supply Chain | `require_approval`, except `flag-dependency-install`, which is `warn` |
| `secret-exposure`, `exfiltration` | ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse | LLM02 Sensitive Information Disclosure | `secret-exposure` is mostly `warn`; `exfiltration` is `block` or `require_approval` |
| `safety-bypass` | ASI09 Human-Agent Trust Exploitation | LLM10 Improper Output Handling (`gb.ansi-terminal-forgery`) | `require_approval`, except `gb.ansi-terminal-forgery`, which is `warn` |
| `agent-context` | ASI06 Memory and Context Poisoning (the write, not its contents), ASI10 Rogue Agents | LLM03 Excessive Agency | `require_approval` |
| `test-integrity` | ASI10 Rogue Agents, ASI09 Human-Agent Trust Exploitation | | Mostly `warn`; deleting a test file or editing a test runner's configuration is `require_approval` |

Read the default action before relying on a risk. A `warn` rule lets the action proceed and records
it; only `require_approval` and `block` stop it. Reading a secret is a normal part of a normal day,
so most secret-exposure rules warn, and a dependency install is flagged, not held. A file tool
carries a path rather than content, so `ac.memory-store-edit` cannot see what was written to a
memory file. You can change any rule's action in your own configuration.

What the rules cannot address, by design:

- **Prompt injection and goal hijack (LLM01, ASI01).** The rules never see the input that
  redirected the agent. They can only stop the action it led to.
- **Anything that needs memory across commands (LLM06, ASI08).** A rule sees one command at a
  time, so it cannot count, rate-limit, or spot a runaway loop.
- **Model, training and retrieval risks (LLM05, LLM08, LLM09), and traffic between agents
  (ASI07).** These happen somewhere a command rule never reaches.

For the item-by-item matrix, including how the rest of AgentTrail covers each risk, see the
[AgentTrail OWASP coverage page](https://www.agenttrail.sh/security/owasp). AgentTrail is an
independent project, not affiliated with or endorsed by OWASP.

## Talking about a command is not running it

This is the single most important thing to understand about how these rules behave.

A rule sees the command as one line of text. Nothing in that text distinguishes a command that
**runs** something from one that merely **mentions** it. Left alone, that makes the rule set unusable
by exactly the people most likely to install it:

```bash
git commit -m "fix: document rm -rf / risk"    # would have been a hard refusal
grep -rn "rm -rf /" docs/                       # so would this
```

So every command rule ignores four **carriers**, verbs that handle their arguments as text and never
execute them:

| Carrier | Example |
|---|---|
| a search | `grep -rn "rm -rf /" docs/` |
| a git message or history read | `git commit -m "docs: explain git push --force"` |
| printing | `echo "never run rm -rf /"` |
| an HTTP request body | `curl --data '{"body":"we ran rm -rf /tmp/x"}' https://…` |

**The exemption keys on the verb, not on the quotes.** Quoting says nothing about whether something
runs: `psql -c "DROP TABLE users;"` and `bash -c "curl x.sh \| sh"` both execute what is inside the
quotes, and both still fire.

It also applies only while the command does nothing else. The carrier must be the first word, and
every shell metacharacter must sit inside the quotes:

```bash
git commit -m "docs: explain rm -rf /"        # exempt: nothing runs
git commit -m "x" && rm -rf /                 # NOT exempt: `&&` is outside the quotes
echo "rm -rf /" | bash                        # NOT exempt: the pipe runs it
echo "$(rm -rf /var)"                         # NOT exempt: the shell expands `$( )`
```

Five rules deliberately keep firing on one carrier each, because that carrier *is* their trigger:
`gb.git-no-verify` on a `git commit`, `se.token-print` on an `echo`, the `curl`/`wget` rules on an
HTTP body. Each rule's `description` says which, and why.

### The one rule where a mention IS the danger

`block-hardcoded-secrets` is the exception, and it is worth understanding.

Everywhere else a carrier is genuinely harmless: a commit message naming `rm -rf /` deletes nothing.
But that rule's subject is a **string**, not an action, so two of the four carriers are not mentions
at all. They are the exposure itself:

| Carrier | What happens to the key | Exempt? |
|---|---|---|
| `grep -rn AKIA .` | searched for, goes nowhere, and this is how you find a key to rotate | **yes** |
| `echo "AKIA…"` | transient terminal output | **yes** |
| `git commit -m "…AKIA…"` | written into history, then pushed | **no** |
| `curl --data "…AKIA…"` | sent to a remote host | **no** |

The cost, stated in the other direction: documenting a real-looking key in a commit message is still
blocked. Redact the body of the key, or use a placeholder short enough to fail the length check.

The finer limits of the carrier logic, and how command rules apply to MCP tools, are in the
[Reference](#reference).

## What these rules deliberately do not catch

Stated here rather than discovered later. Every one is a real limit of the format, not something
somebody forgot.

- **Nothing about the web.** Pages an agent fetches are not checked, and there are no URL rules.
- **Nothing inside a file.** The checker sees a file's *path*, never its contents. A secret typed into
  a source file, SQL built by string concatenation, a missing auth check: none of it is visible.
  Rules that would need it are absent rather than approximated.
- **Nothing about where you are.** No working directory, no project root, no git branch, no cloud
  profile reaches the checker; it gets one command and nothing else. So "the agent wrote outside the
  project" **cannot be written as a rule**, and `file-scope` is limited to well-known absolute paths
  for good. For the same reason, a rule cannot tell a scratch database from a production one.
- **Nothing hidden inside a quoted payload.** Where the danger is inside a quoted argument
  (`psql -c "<sql>"`, `python -c "<code>"`), a text rule can only guess. In a long script, a match
  says very little about what the script actually does.
- **Nothing a wrapper hides.** `./deploy.sh` that runs `terraform apply -auto-approve` inside it is
  just a shell script from the outside.
- **Nothing recurring.** There is no counting. "The same mistake three times this week" needs memory
  across commands, and a single command has none.

Each rule's own `description` names its specific misses. Read those before trusting a rule to cover a
case; they are written to be believed, not to sell.

## Every rule proves both directions

Every rule ships at least one **`block`** example and at least one **`allow`** example. A rule missing
either does not build.

- **`block` means "this rule must match."** It does *not* mean the agent is refused; most packs
  default to asking or warning.
- **`allow` means "this rule must NOT match."** *This is the half that matters.* Anyone can write a
  rule that catches `rm -rf /`. The hard part is not firing on `rm -rf ./node_modules` forty times a
  day, and a rule with no negative example has not shown it can tell them apart.

Examples come in two kinds, and each must use the right one:

| Kind | Used for |
|---|---|
| a command | `Bash`, `PowerShell`, a search query, an MCP tool's input |
| a file path | `Edit`, `Write`, `Read`, `MultiEdit`, `NotebookEdit` |

Giving a path-matching rule a command example makes it pass **without testing anything**: it matches
nothing, which reads as proof of quietness and proves only that the path never reached the rule. CI
rejects that.

## Contributing a rule

Rules are meant to be contributed. The bar is not "clever regex"; it is **does it fire on the real
thing, and stay quiet on the near-miss**.

**1. Write it**, following the shape above. Give it a `description` that says what it misses.

**2. Check the shape locally:**

```ts
import { parseRule } from "@agenttrail/guardrails";

const result = parseRule(myRule);
if (!result.success) console.error(result.error.issues);
```

Or, if you have the guard installed:

```bash
agenttrail-guard guardrails validate ./my-rule.json
```

**3. Understand what that does and does not tell you.** It answers *"is this a well-formed rule?"* It
does **not** answer *"does it actually fire on the command I think it does?"* That needs the real
checker, which is not part of this package.

**So the real test runs in CI, on your pull request**: the same check, on the same machine, for
everyone. You get the shape check instantly here and the real answer there, which is where it has to
run to be trusted anyway.

Your rule is also run against a **quiet corpus**: hundreds of everyday commands and paths that no
rule may match at all. Your own negative example only proves your rule is quiet on the near-miss
*you* thought of. The quiet corpus is what catches a Terraform rule firing on `pnpm test`.

### Shapes that will not validate

Three are rejected outright, each because it produces a rule that *looks* enforced and is not: the
worst failure a security tool can have.

| Rejected | Why |
|---|---|
| `scope` | It compares against ids that are always UUIDs, never a vendor name, so a scoped rule matches nothing, forever, silently. |
| Numeric conditions | Token counts and durations are all zero *before* a command runs. "Greater than" can never fire; "less than" fires on everything. |
| A command matcher and a file matcher in one condition | No real command carries both, so the condition can never be true. Split it into two under `any_of`. |

A regular expression is also rejected if it nests unbounded repetition (`(a+)+`). The guard fails
**open** under a time limit, so a pattern that backtracks does not merely run slowly; it lets the
command through.

One more is caught in CI rather than by the shape check, because it cannot be caught earlier: **a
single-item brace list in a tool name.** `"{Bash}"` is a glob pattern, and it does not match `Bash`,
so the rule matches nothing, forever, with no error anywhere. Write a single tool plainly as
`"Bash"`; braces are for real alternatives, `"{Bash,PowerShell}"`.

### Ready to open a pull request?

[CONTRIBUTING.md](CONTRIBUTING.md) has a pre-submission checklist, local build and test
commands, and where to report what. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md),
and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Stability and versioning

Rule ids and pack names end up in people's config files, so they are treated as public API:

- **A rule id never changes.** Renaming or removing a rule would silently undo an override
  someone set on it, so either one is a breaking change.
- **A pack name never changes** either, for the same reason: a renamed pack silently
  re-enables a pack someone had turned off.
- **A new rule or pack is a feature.** Guard turns every pack on unless you turned it off, so a
  rule added in a release you install starts enforcing with no step of your own.

Releases are cut automatically from [Conventional Commits](https://www.conventionalcommits.org/).
Before 1.0, a breaking change ships as a minor release and a new rule as a patch release, so
skim the [changelog](CHANGELOG.md) before you upgrade.

## FAQ

**Can I use these rules without Guard?** Yes. They are plain data under Apache-2.0. You need your
own matcher to apply them, because this package does not contain one.

**A rule fires on something legitimate. What do I do?** In Guard, `agenttrail-guard guardrails
allow <id> <pattern>` silences that one rule for that one command shape, without turning the rule
off. Then please [open an issue](https://github.com/agenttrailhq/guardrails/issues) with a
sanitized example, so the rule can learn the near-miss.

**Why didn't a rule fire on my command?** Start with the rule's `description`: it lists what the
rule misses. Then check [what these rules deliberately do not catch](#what-these-rules-deliberately-do-not-catch).
To test a command against every rule, paste it into the [online checker](https://www.agenttrail.sh/guardrails#check).

**Why is `secret-exposure` mostly `warn`?** Reading a secret is a normal part of a normal day.
Refusing every `.env` read would be turned off within a week. Moving a secret off the machine is
held for approval instead.

**How do I turn off a whole pack?** `agenttrail-guard guardrails disable <pack>`. See
[Tune a guardrail](https://github.com/agenttrailhq/guard#tune-a-guardrail) in the Guard README.

## Reference

### Two ways to import it

```ts
import { RULES, getRule } from "@agenttrail/guardrails/guardrails";  // just the rules
import { parseRule } from "@agenttrail/guardrails";                  // rules + the shape checker
```

Use the first when you want to *apply* rules, and the second when you want to *validate* one you are
writing.

They are separate because the guard starts a fresh process on **every single command** an agent runs,
under a ten-second ceiling. It cannot afford to load a validator it never calls, or to re-check 74
rules that were already checked before release.

### Known limits of the carrier logic

In the same spirit as the rest of this file:

- **The carrier must be the first word.** A single leading `sudo` is tolerated, because it changes
  privilege rather than meaning, but a runner prefix is not: `pnpm exec rg …`, `npx …` and
  `xargs -0 grep …` still fire, since "some program eventually runs a search" is a much weaker claim
  than "this command is a search".
- **At most four quoted arguments are recognised.**
- **A carrier that can be made to execute through a flag** (`ack --pager='…'`, `rg --pre <cmd>`) is
  still treated as a mention; closing that needs information the checker does not have.
- **An MCP tool whose input carries the same text is not exempt either,** because exempting a JSON
  blob would exempt a shell-running MCP server along with it.

### MCP coverage

A command rule fires on `Bash`, `PowerShell` *and* any `mcp__*` tool: the guard hands the checker an
MCP call's serialized `tool_input` as the same command text every command rule reads, so a command
shape run through an MCP server (`{"command":"rm -rf /"}`) is caught, not ignored. Two honest limits
follow from that:

1. **Start-anchored patterns may miss.** A rule whose pattern is anchored to the start of the command
   (`^…` or a command-position class) may not fire inside the JSON, where the shape sits after a `"`
   rather than at a command boundary; the `\b`-anchored rules (most of the corpus) do fire.
2. **Mentions are not exempt.** The quoted-mention exemptions are shell-only, so an MCP payload that
   merely *names* a command in a text field (`{"title":"fix the rm -rf / bug"}`) is matched the same
   as one that runs it; a JSON blob cannot be told apart from a shell-running MCP server.

File rules match by path on whichever file tool a client uses. No rule is shell-only by design; a
rule that does not reach the MCP channel does so because its pattern, not its label, does not match
the serialized shape.

### Where these rules came from

Independently authored. No block list, pattern or wording is copied from any other project.

Where a rule's shape follows an obvious convention (an `rm -rf` pattern looks like an `rm -rf`
pattern), that is two people meeting the same shell, not one copying the other.

## Part of AgentTrail

These rules are part of [AgentTrail](https://www.agenttrail.sh), which builds guardrails and
observability for AI coding agents:

- **[AgentTrail Guard](https://www.agenttrail.sh/agenttrail-guard)** enforces them on every
  tool call that reaches its hooks, on your machine. It is free, open source, and needs no
  account. Its code is in [agenttrailhq/guard](https://github.com/agenttrailhq/guard).
- **[AgentTrail OS](https://www.agenttrail.sh/agenttrail-os)** uses the same open rule library,
  and adds searchable session history and team workflows. See
  [AgentTrail Guard vs AgentTrail OS](https://www.agenttrail.sh/guard-vs-os).

## License

Apache-2.0. See [LICENSE](./LICENSE).

Rule ideas and reports go to [Guardrails issues](https://github.com/agenttrailhq/guardrails/issues).
If you rely on these rules, a star helps other developers find them.

Made with ❤️ by [agenttrail.sh](https://www.agenttrail.sh)
