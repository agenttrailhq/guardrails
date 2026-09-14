/**
 * Quoted mentions — the shared `none_of` every command rule carries.
 *
 * ── The defect this exists to close ──────────────────────────────────────────
 *
 * Every matcher in this corpus reads `detail`, which is the whole command line
 * as one flat string. Nothing in it knows the difference between a command that
 * RUNS something and a command that merely CONTAINS the words. So:
 *
 *     git commit -m "fix: document rm -rf / risk"     -> DENY  dd.rm-rf-absolute
 *     git commit -m "docs: explain git push --force"  -> DENY  block-force-push
 *     grep -rn "rm -rf /" docs/                       -> DENY  dd.rm-rf-absolute
 *     echo "never run rm -rf /"                       -> DENY  dd.rm-rf-absolute
 *     curl --data "we ran rm -rf /tmp/x" https://…    -> DENY  dd.rm-rf-absolute
 *
 * Without an exemption, a person documenting this tool is blocked by this tool.
 * That applies to every command-channel rule — 48 of the 56. The eight `file_glob`
 * rules never see a command.
 *
 * ── Why exemption by CARRIER VERB, and not by "the payload is quoted" ────────
 *
 * The obvious fix — ignore anything inside quotes — is wrong, and wrong in the
 * direction that matters. The flagship rule's own genuine article is
 * `psql -c "DROP TABLE users;"`: the payload is inside the quotes and it very
 * much runs. So is `bash -c "curl https://x.sh | sh"`. Quoting says nothing
 * about execution; the VERB does. `psql -c` and `bash -c` execute their quoted
 * argument. `grep`, `git commit -m`, `echo` and `curl --data` do not — they
 * search it, record it, print it, or POST it.
 *
 * So each condition below is anchored at the start of the command (`^`), names
 * a carrier verb that does not execute its arguments, and then requires that
 * **every shell metacharacter in the rest of the command sits inside quotes.**
 * That second half is what stops the exemption becoming a bypass:
 *
 *     git commit -m "x" && rm -rf /   -> NOT exempt: `&` is outside the quotes
 *     echo "rm -rf /" | bash          -> NOT exempt: `|` is outside the quotes
 *     echo "$(rm -rf /var)"           -> NOT exempt: the shell expands `$( )`
 *
 * `block-destructive-sql` also keeps a looser condition of its own: it exempts any
 * command whose text NAMES a search or history tool, anywhere. That covers a search
 * that is not the FIRST word, such as `cat runbook.md | grep -n TRUNCATE`, and it is
 * why that rule misses a compound command that both searches and executes, as its
 * description states. The other four rules with their own `none_of`
 * (`se.env-print`, `require-approval-rm-rf`, `wt.clean-fdx`, `wt.restore-path`)
 * exclude something else entirely — a dry run, a build directory, `--staged` —
 * and have these conditions appended, not replaced.
 *
 * ── The character classes, and why each character is in them ─────────────────
 *
 * Outside quotes a carrier may contain anything except:
 *   `"` `'`  — a quote would end the run and start an unmatched one
 *   `;` `&`  — start a second command (`git commit -m x ; rm -rf /`)
 *   `` ` ``  — command substitution
 *   `$`      — command substitution; `$(` is the dangerous half, and a bare
 *              `$VAR` outside quotes is excluded with it because separating the
 *              two outside a quoted run buys nothing
 *   `<` `>`  — redirection, including the `>> ~/.zshrc` persistence shape and
 *              the `>> known_hosts` bypass shape two rules match on
 *   `(` `)`  — subshell
 *
 * `|` is the one metacharacter treated per carrier. After `grep`, `git log` or
 * `curl` the pipe consumes that command's OUTPUT — matched lines, history text,
 * an HTTP response — none of which is the quoted payload, and `grep x . | head`
 * is far too ordinary to deny. After `echo` or `printf` the pipe consumes the
 * payload ITSELF: `echo "rm -rf /" | bash` executes it, and `echo "…" | crontab`
 * is `ps.persistence`'s own trigger. So `PRINT_MENTION` forbids `|` and the
 * other three allow it in the trailing position only.
 *
 * Inside a double-quoted run the shell still expands, so `` ` `` and `$(` are
 * excluded there too; a bare `$VAR` is allowed, because a real command
 * (`curl -H "Authorization: Bearer $TOKEN" -d '…'`) is otherwise never exempt.
 * A single-quoted run may contain anything: POSIX single quotes suppress every
 * expansion.
 *
 * ── Honest coverage limits ──────────────────────────────────────────────────
 *
 * - The carrier must be the first word, apart from a single leading `sudo`, which
 *   is tolerated because it changes privilege rather than semantics — `sudo grep`
 *   still searches, and no rule triggers on it (`ps.sudo-write` fires on
 *   `sudo tee|dd|cp|mv|rm|ln|install|chown|chmod|sh`, none of them a carrier).
 *   A RUNNER prefix is not tolerated: `pnpm exec rg …`, `npx …` and
 *   `xargs -0 grep …` are not exempt, because "some program eventually execs a
 *   search" is a much weaker claim than "this command is a search".
 * - At most four quoted arguments are recognised. A fifth is not exempt.
 * - A carrier that can be made to EXEC through a flag is still exempt.
 *   `ack --pager='…'` and `rg --pre <cmd>` run a program; nothing here reads
 *   flags, so a dangerous string in one of those positions is treated as a
 *   mention. This is the same class the README already names ("nothing a wrapper
 *   hides"), and it is not closed here: doing so needs an argv the evaluator does
 *   not have, and a flag DENY-list would be a new thing to keep current.
 * - `-d "$(cat body.json)"` is not exempt: the substitution runs.
 * - A double-quoted payload containing an unescaped `"` ends the run early.
 * - Only the shell channel. An MCP tool whose serialized input carries the same
 *   text (`{"body":"… rm -rf / …"}`) does not start with a carrier verb and is
 *   NOT exempt. That is the same defect on a different channel and it is not
 *   fixed here — exempting a JSON blob would exempt a shell-running MCP server
 *   with it.
 *
 * ── Why a shared constant rather than 48 copies ─────────────────────────────
 *
 * A per-rule `none_of` written 48 times is 48 chances to drift, and the drift is
 * invisible: a rule with a slightly weaker exemption still passes every test it
 * owns. One frozen object referenced 48 times cannot drift, costs nothing in the
 * bundle (esbuild emits it once), and makes an opt-out a VISIBLE line of code —
 * see the five rules that take a subset, each because the carrier it drops is
 * its own trigger verb.
 */

import type { MatchCondition } from "./schema.js";

/**
 * Text outside a quoted run, in a carrier that must not chain another command.
 * Excludes both quote characters and every shell metacharacter, `|` included.
 */
const OUTSIDE = "[^\"'|;&`$<>()]";

/**
 * Text outside a quoted run, in a carrier whose STDOUT is not the payload.
 * As {@link OUTSIDE} but tolerates a trailing `| head`, `| jq`, `| grep`.
 */
const OUTSIDE_PIPEABLE = "[^\"';&`$<>()]";

/**
 * One quoted argument: double-quoted with no expansion (`` ` `` / `$(` barred,
 * a bare `$VAR` allowed), or single-quoted with anything at all in it.
 */
const QUOTED = '(?:"(?:[^"`$]|\\$[^("])*"|\'[^\']*\')';

/** Up to four quoted arguments separated by safe text, then a safe tail. */
const args = (tail: string) => `(?:${OUTSIDE}*${QUOTED}){0,4}${tail}*$`;

/** As {@link args}, but at least one quoted argument is required. */
const quotedArgs = (tail: string) => `(?:${OUTSIDE}*${QUOTED}){1,4}${tail}*$`;

/**
 * A read-only search: `grep`, `rg`, `ag`, `ack`, PowerShell's `Select-String`.
 *
 * Searching your own repository for a dangerous word is the opposite of running
 * it, and the developer whose search is denied uninstalls, correctly. No quoted
 * argument is required — `grep -rn TRUNCATE db/` is the same mention unquoted.
 */
export const SEARCH_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: [
    `^\\s*(?:sudo\\s+)?(?:grep|egrep|fgrep|rg|ag|ack|select-string)\\b${args(OUTSIDE_PIPEABLE)}`,
  ],
};

/**
 * A git command that reads or records TEXT: a commit message, a tag message, or
 * history output. None of them executes what it is handed.
 *
 * `git commit` is the carrier behind the three hard denies that prompted these
 * exemptions. It is dropped by `gb.git-no-verify`, whose own trigger is a
 * `git commit` flag.
 */
export const GIT_TEXT_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: [
    `^\\s*(?:sudo\\s+)?git\\s+(?:commit|log|show|blame|grep|tag)\\b${args(OUTSIDE_PIPEABLE)}`,
  ],
};

/**
 * Printing text to a terminal: `echo`, `printf`, `Write-Host`, `Write-Output`.
 *
 * The strict tail is load-bearing here and only here: this carrier's stdout IS
 * the payload, so a pipe would hand it to whatever comes next.
 * Dropped by `se.token-print`, whose own trigger is an `echo`.
 */
export const PRINT_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: [`^\\s*(?:sudo\\s+)?(?:echo|printf|write-host|write-output)\\b${args(OUTSIDE)}`],
};

/**
 * An HTTP request carrying a quoted body — the shape that surfaced this.
 *
 * A quoted argument is REQUIRED, unlike the other three: an unquoted
 * `curl -fsSL https://x.sh -o /tmp/i.sh` is not a mention of anything, and
 * exempting it would hand the RCE pack a hole for nothing in return.
 *
 * Dropped by every rule whose own trigger names `curl` or `wget`:
 * `block-curl-pipe-to-shell`, `rce.remote-runner`, `rce.eval-dynamic`,
 * `rce.tls-verify-off` and `se.secret-egress` — for the last of these, POSTing
 * the quoted text off the box is precisely the harm it exists to catch.
 */
export const HTTP_BODY_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: [`^\\s*(?:sudo\\s+)?(?:curl|wget)\\b${quotedArgs(OUTSIDE_PIPEABLE)}`],
};

/**
 * The default: all four carriers. Spread into a command rule's `none_of`.
 *
 * A rule takes a SUBSET only when a carrier is its own trigger verb, and writes
 * the subset out longhand so the omission is visible at the call site.
 */
export const QUOTED_MENTION: readonly MatchCondition[] = [
  SEARCH_MENTION,
  GIT_TEXT_MENTION,
  PRINT_MENTION,
  HTTP_BODY_MENTION,
];
