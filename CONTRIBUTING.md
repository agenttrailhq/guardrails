<!-- cspell:words hostnames agenttrailhq dedup -->

# Contributing to AgentTrail Guardrails

Thanks for helping these guardrails get sharper. A clear report of a false positive or a missed
command is just as valuable as a new guardrail, and the README sets out
[what a good guardrail needs](README.md#contributing-a-guardrail).

By taking part, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). To report a
security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Where to report what

| You found… | Where it goes |
|---|---|
| A guardrail firing on a legitimate command | [Guardrails issues](https://github.com/agenttrailhq/guardrails/issues) |
| A dangerous command no guardrail catches | [Guardrails issues](https://github.com/agenttrailhq/guardrails/issues) |
| A bug in the hook, CLI, install, or scan report | [Guard issues](https://github.com/agenttrailhq/guard/issues) |

Share sanitized examples only: remove secrets, tokens, internal hostnames, and private
project details.

## Writing a guardrail

The guardrail format, the pack a guardrail belongs in, how to check its shape, and the shapes that
will not validate are all in the README:

- [A guardrail, start to finish](README.md#a-guardrail-start-to-finish)
- [Every guardrail proves both directions](README.md#every-guardrail-proves-both-directions)
- [Contributing a guardrail](README.md#contributing-a-guardrail)

A guardrail may carry an optional `owasp` field: the ids of the OWASP risks it addresses, such as
`["ASI02", "LLM03"]`. Versions up to and including 0.2.2 reject any key they do not know, so
validate a guardrail that carries `owasp` with 0.2.3 or later, or with a guard built on it.

Before writing a new guardrail, paste the command into the
[online checker](https://www.agenttrail.sh/guardrails#check) to see whether a guardrail already
catches it.

## Write a guardrail with your coding agent

Using Claude Code, Cursor, or Codex CLI? From a fresh clone, paste this prompt into your agent
and fill in the last line of step 2:

```text
You are helping me add a guardrail to AgentTrail Guardrails, the repository in this directory.
1. Read README.md (especially "A guardrail, start to finish", "Every guardrail proves both directions",
   and "Contributing a guardrail") and CONTRIBUTING.md.
2. The guardrail should catch: <describe the dangerous command or file change>.
3. Choose the pack for the harm it prevents, then add one file under src/packs/<pack>/,
   following the neighboring files, and register it in that pack's index.ts.
4. Give it a stable id, a description that says what it catches and what it misses, and
   at least one `block` and one `allow` fixture of the right kind.
5. Give it an `owasp` list, add it to OWASP_TAGS in __tests__/corpus.test.ts, update the
   guardrail counts the tests pin in __tests__/corpus.test.ts and __tests__/dedup.test.ts,
   and update the counts in README.md.
6. Run `pnpm test`, `pnpm lint`, `pnpm spell`, and `pnpm typecheck`, and fix any failure.
7. Suggest a Conventional Commit message. Do not push or publish.
```

## Submit a guardrail

A guardrail you wrote for yourself can protect everyone. These steps take it from your machine
to a pull request here.

### 1. Fork and clone

Fork [agenttrailhq/guardrails](https://github.com/agenttrailhq/guardrails), then clone your fork
and install it as shown in [Build and test locally](#build-and-test-locally).

### 2. Export your guardrail, or write the file

If you added it with `agenttrail-guard guardrails add`, export it:

```bash
agenttrail-guard guardrails export <id>
```

This writes a JSON draft with the right id prefix for its pack and blanks marked `FILL IN` for
its examples, its OWASP ids and, where yours had none, its title and description. Fill them in
(see step 4), then check the draft and export it again to get the library file:

```bash
agenttrail-guard guardrails validate <draft>.json
agenttrail-guard guardrails export <draft>.json
```

`validate` refuses a draft that still has a blank, and `export` writes nothing until the draft
passes. The second `export` prints the exact lines for step 3.

You can also write the file by hand: copy a neighboring file in the same pack and change it.

### 3. Put it in its pack

The file goes in `src/packs/<pack>/`, named after its id (`wt.stash-drop` is
`wt-stash-drop.ts`). Pick the pack for **the harm it prevents**, not the technique it uses. Ids
start with the pack's prefix:

| Pack | Prefix | Pack | Prefix |
|---|---|---|---|
| `working-tree` | `wt.` | `privilege-supply-chain` | `ps.` |
| `destructive-data` | `dd.` | `file-scope` | `fs.` |
| `prod-infra` | `pi.` | `agent-context` | `ac.` |
| `secret-exposure` | `se.` | `test-integrity` | `ti.` |
| `rce-supply-chain` | `rce.` | `exfiltration` | `ex.` |
| `safety-bypass` | `gb.` | | |

Register it in the pack's `index.ts` twice: an `import` line, and an entry in the `rules` list.
Then update what the tests pin:

- the total and the pack's count in `__tests__/corpus.test.ts`, and the total in
  `__tests__/dedup.test.ts`;
- its id and OWASP ids in `OWASP_TAGS` in `__tests__/corpus.test.ts`;
- the totals and the pack's row in `README.md`, and the pack's row in the
  [OWASP coverage](README.md#owasp-coverage) table if it cites an id that row does not list yet.

### 4. Write good examples

- **`block`: the real thing.** The command or path the guardrail exists to stop, written the
  way an agent would run it. Add the variants it must still catch: another flag order, a path
  prefix, `PowerShell` as well as `Bash` if it applies.
- **`allow`: the near-miss.** The command that looks closest but is safe, such as `git stash
  list` next to `git stash drop`. This is the half that matters: a guardrail that has never
  been shown a near-miss has not shown it can tell the two apart.
- **The right kind.** A command for a command guardrail (`bash()`, `pwsh()`), a file path for a
  file guardrail (`file()`). An example of the wrong kind matches nothing and passes without
  testing anything.
- **Mentions are not uses.** Spread `...mentions("<the command>")` into `allow` so a commit
  message, a search, an `echo` or a `curl` body that only names the command is left alone.

The description must be at least 120 characters and say what the guardrail does **not** catch.
The title must say what it stops, not repeat the id. Match commands with `detail_matches` (a
regular expression, matched case-insensitively), not `detail_contains`. List at least one OWASP
id in `owasp`, agentic ids before LLM ids, each ascending.

### 5. Check it

```bash
pnpm test
pnpm lint
pnpm spell
pnpm typecheck
```

`pnpm test` runs your examples and the **quiet corpus**, hundreds of everyday commands and paths
that no guardrail may match.

### 6. Sign off and open a pull request

Sign off every commit:

```bash
git commit -s -m "feat: add a guardrail for <what it catches>"
```

`-s` adds a `Signed-off-by:` line with your name and email. It certifies the
[Developer Certificate of Origin](https://developercertificate.org): that you wrote the change,
or otherwise have the right to submit it under this project's license. If you forgot, add it
to your last commit with `git commit --amend -s`, or to every commit on your branch with
`git rebase --signoff main`.

Push to your fork and open a pull request against `main`, with a
[Conventional Commit](https://www.conventionalcommits.org) title.

### 7. What a reviewer checks

- **Does it fire on the real thing?** Every `block` example is the dangerous command as an
  agent would run it.
- **Does it stay quiet on the near-miss?** The `allow` examples are the closest safe commands,
  not unrelated ones.
- **Does it pass the quiet corpus?** CI runs it against the everyday commands and paths that no
  guardrail may match.
- **Is it in the right pack, with a final id?** An id cannot be renamed after it is merged,
  because users' config files refer to it.
- **Does the description say what it misses, and do its OWASP ids name the risks it
  addresses?**

## Before you open a pull request

- [ ] The guardrail is filed in the pack for **the harm it prevents**, not the technique it uses.
- [ ] Its `id` is final. Renaming it later breaks the configs that reference it.
- [ ] Its `description` says what it catches **and what it misses**.
- [ ] Its `owasp` field lists the OWASP risks it addresses (at least one, in list order), and
      the README's [OWASP coverage](README.md#owasp-coverage) table still matches.
- [ ] It has at least one `block` example and at least one `allow` example.
- [ ] Every commit is signed off (`git commit -s`).
- [ ] Each example is the right kind: a command for command guardrails, a file path for file guardrails.
- [ ] It uses none of the rejected shapes: `scope`, numeric conditions, a command matcher and a
      file matcher in one condition, nested unbounded repetition, or a single-item brace list.

## Build and test locally

This repository uses the pnpm version pinned in `package.json`; CI runs on Node.js 22.

```bash
git clone https://github.com/agenttrailhq/guardrails.git
cd guardrails
pnpm install --frozen-lockfile
pnpm test
pnpm lint
pnpm spell
pnpm typecheck
```

Use Conventional Commit messages, such as `feat: add a guardrail for …` or `fix: stop … firing on …`;
CI checks commit messages on pull requests.

## License

This library is licensed under the [Apache License 2.0](LICENSE). Under section 5 of that
license, a contribution you submit for inclusion is provided under the same terms, unless you
state otherwise.
