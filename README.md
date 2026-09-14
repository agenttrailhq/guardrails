<!-- cspell:words kubeconfig -->

# @agenttrail/guardrails

**A library of rules that spot dangerous commands before an AI coding agent runs them.**

56 rules, grouped into 8 packs. Apache-2.0.

---

## What this is, in plain terms

When you let an AI coding agent work in your terminal, it eventually proposes something you would
not have typed yourself — `git reset --hard` over a day's work, `rm -rf` on the wrong path, a
`terraform apply` against production.

This package is the **list of things worth stopping**, written as data. Each entry says what to look
for, how serious it is, and what should happen — allow it, ask a human first, or refuse.

**That is all this package does.** It contains no code that watches your machine and nothing that
talks to the network. It is a list. Something else has to read it and act on it — normally
[`agenttrail-guard`](https://github.com/agenttrailhq/guard), which runs on your laptop and checks each
command an agent proposes against these rules.

Separating the two is deliberate. You can read every rule here, disagree with one, and change it,
without trusting anything about the tool that enforces them.

## Who this is for

- **You use an AI coding agent** and want a sensible default set of guardrails rather than writing
  your own from scratch.
- **You want to see exactly what is being blocked and why.** Every rule is plain data with a written
  explanation, including what it *misses*.
- **You want to contribute a rule** you wish had existed. See [Contributing](#contributing-a-rule).

## Install

```bash
npm install @agenttrail/guardrails
```

Most people never install this directly — `agenttrail-guard` bundles it. Install it yourself if you
are writing rules, or building your own tool on top of the list.

## A rule, start to finish

Here is a complete rule. Nothing is hidden; this is the actual shape.

```jsonc
{
  "id": "wt.reset-hard",
  "category": "working-tree",
  "severity": "high",
  "defaultAction": "block",
  "title": "git reset --hard discards uncommitted work",
  "description": "Discards all uncommitted changes. Does not match `git restore` — see wt.restore-path.",

  // What to look for. This one matches a Bash command against a regular expression.
  "match": {
    "any_of": [
      { "kind": "execute_tool", "label": "Bash", "detail_matches": ["\\bgit\\s+reset\\s+--hard\\b"] }
    ]
  },

  // Proof it works, in both directions — see "Every rule proves both directions" below.
  "fixtures": {
    "block": ["git reset --hard"],
    "allow": ["git reset src/api.ts"]
  }
}
```

Reading the fields:

| Field | What it means |
|---|---|
| `id` | A stable name. Users type it to disable or change a rule, so it never changes. |
| `severity` | How bad the thing being caught is: `critical`, `high`, `medium`, `low`, `info`. **It is not a price** — this package ships no mapping from severity to money. |
| `defaultAction` | What should happen: `block` (refuse), `require_approval` (ask a human), or `warn` (allow, but say so). A user can override it. |
| `description` | What the rule catches **and what it misses**. The honest limits are part of the rule, not a footnote. |
| `match` | The condition. `any_of` means "any one of these is enough". |
| `fixtures` | Examples that must match, and examples that must not. |

## The eight packs

A rule is filed by **the harm it prevents**, never by the technique it uses to spot it.

That sounds like a detail and is not. The three rules about production config, `.env` files and API
endpoints all work by matching file paths — but they are *not* in `file-scope`. Someone who turned
that pack off to stop path noise would otherwise silently lose their production and secret
protection, which they never asked to turn off and would not know they had.

| Pack | Rules | What it is about |
|---|---:|---|
| `working-tree` | 9 | Destroying uncommitted work or published history — `git reset --hard`, `git clean -fd`, force-push, `rm -rf`. |
| `destructive-data` | 8 | Data git cannot bring back — a dropped volume, a dropped database, destructive DDL, a deleted shadow copy. |
| `prod-infra` | 8 | Changing running infrastructure — Terraform, Kubernetes, Helm, cloud deletes, a deploy that names production. |
| `secret-exposure` | 10 | Credentials and sensitive data leaving where they live. Mostly `warn`: reading a secret is a normal part of a normal day. |
| `rce-supply-chain` | 6 | Running code nobody reviewed — pipe-to-shell, a remote runner, a redirected registry, TLS verification off. |
| `safety-bypass` | 5 | Turning off a check somebody installed on purpose — `--no-verify`, `--admin` merge, hooks disabled, host-key checking off. |
| `privilege-supply-chain` | 6 | Gaining reach or handing it out — `sudo` writes, `chmod 777`, IAM grants, persistence, publishing, new dependencies. |
| `file-scope` | 4 | The agent wrote somewhere it had no business writing — its own config, the machine, git's internals, the CI definition. |

Pack names appear in user config files, so renaming one is a breaking change, not a tidy-up.

## Talking about a command is not running it

This is the single most important thing to understand about how these rules behave.

A rule sees the command as one line of text. Nothing in that text distinguishes a command that
**runs** something from one that merely **mentions** it. Left alone, that makes the rule set unusable
by exactly the people most likely to install it:

```bash
git commit -m "fix: document rm -rf / risk"    # would have been a hard refusal
grep -rn "rm -rf /" docs/                       # so would this
```

So every command rule ignores four **carriers** — verbs that handle their arguments as text and never
execute them:

| Carrier | Example |
|---|---|
| a search | `grep -rn "rm -rf /" docs/` |
| a git message or history read | `git commit -m "docs: explain git push --force"` |
| printing | `echo "never run rm -rf /"` |
| an HTTP request body | `curl --data '{"body":"we ran rm -rf /tmp/x"}' https://…` |

**The exemption keys on the verb, not on the quotes.** Quoting says nothing about whether something
runs — `psql -c "DROP TABLE users;"` and `bash -c "curl x.sh \| sh"` both execute what is inside the
quotes, and both still fire.

It also applies only while the command does nothing else. The carrier must be the first word, and
every shell metacharacter must sit inside the quotes:

```bash
git commit -m "docs: explain rm -rf /"        # exempt — nothing runs
git commit -m "x" && rm -rf /                 # NOT exempt — `&&` is outside the quotes
echo "rm -rf /" | bash                        # NOT exempt — the pipe runs it
echo "$(rm -rf /var)"                         # NOT exempt — the shell expands `$( )`
```

Five rules deliberately keep firing on one carrier each, because that carrier *is* their trigger —
`gb.git-no-verify` on a `git commit`, `se.token-print` on an `echo`, the `curl`/`wget` rules on an
HTTP body. Each rule's `description` says which, and why.

### The one rule where a mention IS the danger

`block-hardcoded-secrets` is the exception, and it is worth understanding.

Everywhere else a carrier is genuinely harmless: a commit message naming `rm -rf /` deletes nothing.
But that rule's subject is a **string**, not an action — so two of the four carriers are not mentions
at all. They are the exposure itself:

| Carrier | What happens to the key | Exempt? |
|---|---|---|
| `grep -rn AKIA .` | searched for, goes nowhere — and this is how you find a key to rotate | **yes** |
| `echo "AKIA…"` | transient terminal output | **yes** |
| `git commit -m "…AKIA…"` | written into history, then pushed | **no** |
| `curl --data "…AKIA…"` | sent to a remote host | **no** |

The cost, stated in the other direction: documenting a real-looking key in a commit message is still
blocked. Redact the body of the key, or use a placeholder short enough to fail the length check.

**Known limits of the carrier logic**, in the same spirit as the rest of this file. The carrier must
be the first word — a single leading `sudo` is tolerated, because it changes privilege rather than
meaning, but a runner prefix is not: `pnpm exec rg …`, `npx …` and `xargs -0 grep …` still fire,
since "some program eventually runs a search" is a much weaker claim than "this command is a search".
At most four quoted arguments are recognised. A carrier that can be made to execute through a flag —
`ack --pager='…'`, `rg --pre <cmd>` — is still treated as a mention; closing that needs information
the checker does not have. And an MCP tool whose input carries the same text is not exempt either,
because exempting a JSON blob would exempt a shell-running MCP server along with it.

## What these rules deliberately do not catch

Stated here rather than discovered later. Every one is a real limit of the format, not something
somebody forgot.

- **Nothing about the web.** Pages an agent fetches are not checked, and there are no URL rules.
- **Nothing inside a file.** The checker sees a file's *path*, never its contents. A secret typed into
  a source file, SQL built by string concatenation, a missing auth check — none of it is visible.
  Rules that would need it are absent rather than approximated.
- **Nothing about where you are.** No working directory, no project root, no git branch, no cloud
  profile reaches the checker — it gets one command and nothing else. So "the agent wrote outside the
  project" **cannot be written as a rule**, and `file-scope` is limited to well-known absolute paths
  for good. For the same reason, a rule cannot tell a scratch database from a production one.
- **Nothing hidden inside a quoted payload.** Where the danger is inside a quoted argument —
  `psql -c "<sql>"`, `python -c "<code>"` — a text rule can only guess. In a long script, a match says
  very little about what the script actually does.
- **Nothing a wrapper hides.** `./deploy.sh` that runs `terraform apply -auto-approve` inside it is
  just a shell script from the outside.
- **Nothing recurring.** There is no counting. "The same mistake three times this week" needs memory
  across commands, and a single command has none.

Each rule's own `description` names its specific misses. Read those before trusting a rule to cover a
case — they are written to be believed, not to sell.

## Every rule proves both directions

Every rule ships at least one **`block`** example and at least one **`allow`** example. A rule missing
either does not build.

- **`block` means "this rule must match."** It does *not* mean the agent is refused — most packs
  default to asking or warning.
- **`allow` means "this rule must NOT match."** *This is the half that matters.* Anyone can write a
  rule that catches `rm -rf /`. The hard part is not firing on `rm -rf ./node_modules` forty times a
  day, and a rule with no negative example has not shown it can tell them apart.

Examples come in two kinds, and each must use the right one:

| Kind | Used for |
|---|---|
| a command | `Bash`, `PowerShell`, a search query, an MCP tool's input |
| a file path | `Edit`, `Write`, `Read`, `MultiEdit`, `NotebookEdit` |

Giving a path-matching rule a command example makes it pass **without testing anything** — it matches
nothing, which reads as proof of quietness and proves only that the path never reached the rule. CI
rejects that.

## Contributing a rule

Rules are meant to be contributed. The bar is not "clever regex" — it is **does it fire on the real
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

**So the real test runs in CI, on your pull request** — the same check, on the same machine, for
everyone. You get the shape check instantly here and the real answer there, which is where it has to
run to be trusted anyway.

Your rule is also run against a **quiet corpus**: 328 everyday commands and paths that no rule may
match at all. Your own negative example only proves your rule is quiet on the near-miss *you* thought
of. The quiet corpus is what catches a Terraform rule firing on `pnpm test`.

### Shapes that will not validate

Three are rejected outright, each because it produces a rule that *looks* enforced and is not — the
worst failure a security tool can have.

| Rejected | Why |
|---|---|
| `scope` | It compares against ids that are always UUIDs, never a vendor name — so a scoped rule matches nothing, forever, silently. |
| Numeric conditions | Token counts and durations are all zero *before* a command runs. "Greater than" can never fire; "less than" fires on everything. |
| A command matcher and a file matcher in one condition | No real command carries both, so the condition can never be true. Split it into two under `any_of`. |

A regular expression is also rejected if it nests unbounded repetition (`(a+)+`). The guard fails
**open** under a time limit, so a pattern that backtracks does not merely run slowly — it lets the
command through.

One more is caught in CI rather than by the shape check, because it cannot be caught earlier: **a
single-item brace list in a tool name.** `"{Bash}"` is a glob pattern, and it does not match `Bash` —
so the rule matches nothing, forever, with no error anywhere. Write a single tool plainly as
`"Bash"`; braces are for real alternatives, `"{Bash,PowerShell}"`.

## Two ways to import it

```ts
import { RULES, getRule } from "@agenttrail/guardrails/guardrails";  // just the rules
import { parseRule } from "@agenttrail/guardrails";                  // rules + the shape checker
```

Use the first when you want to *apply* rules, and the second when you want to *validate* one you are
writing.

They are separate because the guard starts a fresh process on **every single command** an agent runs,
under a ten-second ceiling. It cannot afford to load a validator it never calls, or to re-check 56
rules that were already checked before release.

## Where these rules came from

Independently authored. No block list, pattern or wording is copied from any other project.

Where a rule's shape follows an obvious convention — an `rm -rf` pattern looks like an `rm -rf`
pattern — that is two people meeting the same shell, not one copying the other.

Four vendors' own tools inspired specific rules through their *documented failure modes*, not their
code.

## License

Apache-2.0. See [LICENSE](./LICENSE).
