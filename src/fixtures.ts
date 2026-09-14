/**
 * Fixture constructors — three one-line functions, and no zod.
 *
 * `FixtureSchema` accepts a bare string as shorthand for
 * `{ tool: "Bash", command: … }`, but that shorthand is a **zod transform**: it
 * only becomes the object form when a rule is PARSED. Rule files export plain
 * typed literals so that nothing on the guard's hot path reaches the validator
 * (see `rules.ts`), so there is no parse at load and therefore no transform —
 * a bare string in a rule file would be a bare string at runtime, and the
 * harness reads `"command" in fixture`.
 *
 * Writing every fixture out longhand would work and would be unreadable, so
 * these exist instead. They also make the CHANNEL visible at every single
 * fixture, and the channel is the thing
 * that silently makes a fixture vacuous — a `file_glob` rule handed a command
 * fixture matches nothing, and an `allow` fixture that matches nothing passes.
 */

import type { Fixture } from "./schema.js";

/** A fixture on the command channel, from the `Bash` tool. */
export function bash(command: string): Fixture {
  return { tool: "Bash", command };
}

/**
 * A fixture on the command channel, from the `PowerShell` tool.
 *
 * Worth spelling out at least once per shell rule: on Windows without Git Bash,
 * Claude Code does not register `Bash` at all, so a rule proven only against
 * `Bash` is proven on one platform.
 */
export function pwsh(command: string): Fixture {
  return { tool: "PowerShell", command };
}

/**
 * A fixture on the file channel.
 *
 * `tool` defaults to `Edit`. The guard's mapper routes `Edit`, `Write`, `Read`,
 * `MultiEdit` and `NotebookEdit` to this channel, and file rules deliberately
 * carry no `label`, so which of them a fixture names does not change the answer —
 * it only documents the case being proven.
 */
export function file(filePath: string, tool = "Edit"): Fixture {
  return { tool, file_path: filePath };
}

// ── Quoted-mention near misses ─────────────────────────────────────────────

/**
 * Wrap a payload in shell quotes that will survive the exemption.
 *
 * Double quotes by default, so the common path is the one most fixtures
 * exercise. Single quotes when the payload contains a `"`, a `$` or a backtick —
 * inside double quotes the shell would expand the last two, so the exemption
 * deliberately does not cover them, and a fixture written that way would be
 * testing the wrong thing. A payload carrying BOTH a `'` and one of those three
 * cannot be quoted safely; it is not silently mangled, it simply fails the
 * near-miss assertion, which is the loud outcome.
 */
function quoted(text: string): string {
  return /["$`]/.test(text) ? `'${text}'` : `"${text}"`;
}

/** `git commit -m "…"` — the carrier behind the three hard denies. */
export function mentionInCommit(text: string): Fixture {
  return bash(`git commit -m ${quoted(`docs: explain ${text}`)}`);
}

/** `grep -rn "…" docs/` — searching for the words is not executing them. */
export function mentionInSearch(text: string): Fixture {
  return bash(`grep -rn ${quoted(text)} docs/`);
}

/** `echo "…"` — printing the words is not executing them either. */
export function mentionInEcho(text: string): Fixture {
  return bash(`echo ${quoted(`never run ${text}`)}`);
}

/**
 * `curl --data "…" https://…` — the shape that prompted these exemptions. An
 * agent posting a comment whose BODY discussed `rm -rf` was reported as an
 * `rm -rf` against an absolute path.
 */
export function mentionInPost(text: string): Fixture {
  return bash(`curl --data ${quoted(`we ran ${text}`)} https://api.example.com/comments`);
}

/**
 * All four near misses for one payload: a commit message, a search, an echo and
 * an HTTP body. Spread into a rule's `allow` fixtures.
 *
 * A rule whose own trigger verb IS one of the carriers writes the other three
 * out longhand instead — see `exemptions.ts` for the five that do.
 */
export function mentions(text: string): Fixture[] {
  return [mentionInCommit(text), mentionInSearch(text), mentionInEcho(text), mentionInPost(text)];
}
