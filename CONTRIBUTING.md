<!-- cspell:words hostnames -->

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
5. Update the guardrail counts the tests pin in __tests__/corpus.test.ts, and the counts in
   README.md.
6. Run `pnpm test`, `pnpm lint`, `pnpm spell`, and `pnpm typecheck`, and fix any failure.
7. Suggest a Conventional Commit message. Do not push or publish.
```

## Before you open a pull request

- [ ] The guardrail is filed in the pack for **the harm it prevents**, not the technique it uses.
- [ ] Its `id` is final. Renaming it later breaks the configs that reference it.
- [ ] Its `description` says what it catches **and what it misses**.
- [ ] Its `owasp` field lists the OWASP risks it addresses (at least one, in list order), and
      the README's [OWASP coverage](README.md#owasp-coverage) table still matches.
- [ ] It has at least one `block` example and at least one `allow` example.
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
