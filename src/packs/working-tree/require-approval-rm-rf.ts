// cspell:words doas

import {
  ARG_END,
  QUOTED_MENTION,
  RM_ARGS,
  RM_RECURSIVE,
  RM_WORD,
  SHELL_AND_MCP,
  TEMP_DELETE,
} from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/** The build and cache directories whose removal is exempt. */
const BUILD_DIR =
  "(?:\\./)?(?:node_modules|dist|build|out|coverage|target|\\.next|\\.turbo|\\.cache|\\.vite|\\.parcel-cache)";

/**
 * The id has no dotted pack prefix. Guardrail ids are stable identifiers, so it is not
 * renamed to match the others.
 *
 * The build-directory exemption covers one `rm` whose every argument is a flag, `--`
 * or a build directory, and which ends the command or its segment. The end may also be
 * a closing quote, brace or backslash, which is where an MCP tool's JSON input or a
 * `bash -c "…"` string ends. A subpath of a build directory is exempt, including a
 * dot-led cache such as `node_modules/.vite`, but a path segment may hold at most one
 * leading dot followed by a word character, so `..` segments that leave the directory
 * are not. A build directory followed by any other target is not exempt.
 */
export const requireApprovalRmRf: Rule = {
  id: "require-approval-rm-rf",
  category: "working-tree",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03"],
  title: "Hold `rm -rf` for approval",
  description:
    "Recursive delete: held for approval rather than blocked, which is the right strength for an operation that is destructive but often legitimate. Catches a recursive flag in any argument of the `rm`, with or without force: `-rf`, `-Rf`, `-fr`, `-r -f`, `-r` alone and `--recursive`, before or after the target, and PowerShell's `Remove-Item -Recurse`. Clearing a build directory is EXEMPT (node_modules, dist, build, out, coverage, target, .next, .turbo, .cache, .vite, .parcel-cache, and paths inside them) when every target of that `rm` is one: that shape appears about 220 times in real Claude Code traces against about 3 for a dangerous delete, and a check that asks every time is one people switch off. An absolute path, a $VARIABLE, a ~ path, a source directory, a `..` path out of a build directory, or a build directory followed by another target still asks. `git rm -r --cached` alone, which touches only the index, is exempt. One `rm` or `Remove-Item` whose every target is strictly inside the system temp folder (`/tmp`, `/private/tmp`, `/var/tmp`, the macOS per-user temp folder, `${TMPDIR:?}` on the shell, and the Windows temp folders `C:\\Users\\<name>\\AppData\\Local\\Temp` and `C:\\Windows\\Temp` on any drive, with `\\` between parts, on PowerShell and on Cursor's Shell, which reaches the engine as Bash) is exempt too, so clearing a throwaway checkout does not ask. Still asked: the bare temp folder; `..` anywhere in a target; a glob, brace expansion or backslash in a shell target; in a Windows target, a `/`, a trailing `\\`, a `.` segment, or any character other than letters, digits, `.`, `_` and `-`; a variable after the root; `$TMPDIR`, `$TEMP`, `$TMP`, `$env:TEMP` and `$env:TMP`, which may be unset; any other variable such as `$SCRATCH`; a target outside temp; and a chained second command. Known misses: a delete via a file tool; a build-directory clean-up chained before a second delete in the same command, because the exemption covers the whole command; and an `rm` with more than twelve arguments before the recursive flag. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m \"x\" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${RM_WORD}${RM_ARGS}[ \\t]+${RM_RECURSIVE}${ARG_END}`,
          "\\bremove-item\\b[^|;&]*-recurse",
        ],
      },
    ],
    none_of: [
      ...QUOTED_MENTION,
      ...TEMP_DELETE,
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `${RM_WORD}(?:[ \\t]+-{1,2}[a-z][a-z-]{0,24}){1,8}(?:[ \\t]+--)?(?:[ \\t]+${BUILD_DIR}(?:/\\.?[\\w-][\\w.-]{0,60}){0,4}/?){1,11}[ \\t]*(?:$|[;&|)"'}\\\\])`,
          // A single `git rm --cached`, with no shell metacharacter, touches only the index.
          "^\\s*git(?:\\s+-\\S{1,40}){0,6}\\s+rm\\s[^;&|<>()`$\"'\\n]{0,250}--cached\\b[^;&|<>()`$\"'\\n]{0,250}$",
        ],
      },
    ],
  },
  fixtures: {
    block: [
      bash("rm -Rf /home/user/projects"),
      bash("rm -fr src/generated"),
      bash("rm -rf $HOME/Projects/old-client"),
      pwsh("Remove-Item -Recurse -Force C:/projects/old"),
      bash("rm -r -f src/generated"),
      bash("rm -r ~/old-client"),
      bash("rm -R $HOME/scratch"),
      bash("rm src/generated -rf"),
      bash("rm -rf node_modules ~/projects"),
      bash("rm -rf node_modules/../.."),
      bash("rm -rf node_modules/.."),
      mcp({ command: "rm -rf node_modules ~/projects" }),
      bash("git rm -r src/legacy"),
      bash("git rm -r --cached vendor && rm -r src"),
      // A search or history command piped into a recursive delete is not a mention.
      bash("grep -rl x /srv | xargs rm -rf"),
      bash("grep -rl x /srv |& xargs rm -rf"),
      bash("grep -rl x /srv | env xargs rm -rf"),
      bash("grep -rl x /srv | nice -n 10 xargs rm -rf"),
      bash("grep -rl x /srv | timeout 60 xargs rm -rf"),
      bash("grep -rl x /srv | command xargs rm -rf"),
      bash("grep -rl x /srv | sudo xargs rm -rf"),
      bash("grep -rl x /srv | doas xargs rm -rf"),
      bash("grep -rlZ x /srv | xargs -0 rm -rf"),
      bash("grep -rl x /srv | xargs -I{} rm -rf {}"),
      bash("grep -rl x /srv | parallel rm -rf {}"),
      bash("rg -l x /srv | xargs rm -rf"),
      bash("git grep -l x | xargs rm -rf"),
      bash("git log --name-only --format= | xargs rm -rf"),
      bash("curl -s -d 'q' https://example.com/list | xargs rm -rf"),
      bash("grep -l x . | head -3 | xargs rm -rf"),
      bash("grep -l x . | sort | xargs rm -rf"),
      bash("find . -print0 | xargs -0 rm -rf"),
      bash("grep -rl x /srv \\' | xargs rm -rf \\'"),
      // PowerShell ends a quoted run at a curly quote.
      pwsh("Select-String 'a\u2019; Remove-Item -Recurse -Force C:\\data; \u2019b' f.txt"),
      // The temp exemption is narrow: each of these still asks.
      bash("rm -rf /tmp"),
      bash("rm -rf $TMPDIR"),
      bash("rm -rf /tmp/"),
      bash("rm -rf /tmp/x/../../etc"),
      bash("rm -rf $TMPDIR/../x"),
      bash("rm -rf /tmp/./../etc"),
      bash("rm -rf /tmp/$X"),
      bash(`rm -rf /tmp/\${X}`),
      bash("rm -rf $SCRATCH/x"),
      bash("rm -rf $SCRATCHPAD/x"),
      bash("rm -rf /tmp/a /srv/data"),
      bash("rm -rf /tmp/a && rm -rf /srv/data"),
      bash('rm -rf "$TMPDIR/x"'),
      bash("rm -rf /tmp-old/x"),
      mcp({ command: "rm -rf /tmp/review" }),
      // A temp variable that may be unset, and every way the shell can turn text into `..`.
      bash("rm -rf $TMPDIR/review"),
      bash(`rm -rf \${TMPDIR}/review/`),
      bash("rm -rf $TMP/etc"),
      bash("rm -rf $TEMP/etc"),
      bash("rm -rf /tmp/{..,x}/etc"),
      bash("rm -rf /tmp/a{,/../../etc}"),
      bash("rm -rf /tmp/.\\./etc"),
      bash("rm -rf /tmp/.[.]/etc"),
      bash("rm -rf /tmp/?./etc"),
      bash("rm -rf /tmp/.*/etc"),
      bash("rm -rf /tmp/review/*"),
      bash("rm -r -- /var/tmp/run-7/..cache"),
      pwsh("Remove-Item -Recurse $TMP/Windows"),
      pwsh("Remove-Item -Recurse $TEMP\\..\\Windows"),
      pwsh("Remove-Item -Recurse $env:TEMP\\..\\Windows"),
      pwsh("Remove-Item -Recurse $env:TEMP"),
      // `$env:TEMP` and `$env:TMP` may be unset on macOS and Linux, so they are not roots.
      pwsh("Remove-Item -Recurse -Force $env:TEMP\\review"),
      pwsh("Remove-Item -Recurse $env:TMP/etc"),
      // A comma builds an array, curly quotes are quotes, and `::` starts a provider path.
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x,C:\\Windows"),
      pwsh("Remove-Item -Recurse C:\\Users\\dev\\AppData\\Local\\Temp\\x,C:\\Users"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\u201C,C:\\\u201D"),
      // U+0085 separates arguments in PowerShell, so the second argument here is `\Windows`.
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\u0085\\Windows"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\u200B\\Windows"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\.\\AppData\\Local\\Temp\\x"),
      pwsh(
        "Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\Microsoft.PowerShell.Core\\FileSystem::C:\\Windows",
      ),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\..\\..\\Windows"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp"),
      // `\` is the only Windows separator; `.` alone names the temp folder; no trailing `\`.
      pwsh("Remove-Item -Recurse -Force C:/Users/dev/AppData/Local/Temp/review-1/tests"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\."),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\\"),
      // A brace, a glob class and a wildcard, and a double-dash name PowerShell binds as a path.
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\{..,x}\\etc"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\.[.]\\etc"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\*"),
      pwsh("Remove-Item -Recurse --src C:\\Users\\dev\\AppData\\Local\\Temp\\x"),
      // The same Windows forms through Cursor's Shell, which reaches the engine as Bash.
      bash("Remove-Item -Recurse -Force C:/Users/dev/AppData/Local/Temp/x"),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x,C:\\Windows"),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\u201C,C:\\\u201D"),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x\u0085\\Windows"),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\..\\..\\Windows"),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x C:\\Windows"),
      bash(
        "Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\x; Remove-Item -Recurse C:\\Windows",
      ),
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\."),
      bash("Remove-Item -Recurse -Force $env:TEMP\\x"),
      // On a POSIX shell: a brace, a backslash escape, a glob class, an escaped space.
      bash("rm -rf C:\\Users\\dev\\AppData\\Local\\Temp\\{..,x}\\etc"),
      bash("rm -rf C:\\Users\\dev\\AppData\\Local\\Temp\\.\\.\\etc"),
      bash("rm -rf C:\\Users\\dev\\AppData\\Local\\Temp\\.[.]\\etc"),
      bash("rm -rf C:\\Users\\dev\\AppData\\Local\\Temp\\x\\ /etc"),
    ],
    allow: [
      ...mentions("rm -Rf /home/user/projects"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf node_modules"),
      bash("rm -rf build/"),
      bash("rm -rf dist"),
      bash("./confirm -rf x"),
      bash("rm package-lock.json"),
      bash("rm -r -f node_modules"),
      bash("rm -f -r ./dist"),
      bash("rm -r node_modules dist"),
      bash("rm -rf dist/assets"),
      bash("rm -rf node_modules && pnpm install"),
      bash("git rm -r --cached vendor"),
      bash("docker run --rm -it node:20 npm test"),
      bash("rm -v notes.txt"),
      bash("rm -rf node_modules/.vite"),
      bash('bash -c "rm -r -f node_modules"'),
      mcp({ command: "rm -r -f node_modules" }),
      // Clearing a throwaway checkout inside the system temp folder.
      bash(`rm -rf \${TMPDIR:?}/review`),
      bash(`rm -rf \${TMPDIR:?}/a \${TMPDIR:?}/b`),
      bash("rm -rf /tmp/review-1"),
      bash("rm -rf /private/tmp/agent-1/scratchpad/repo"),
      bash("rm -rf /var/folders/zz/abc123/T/review /tmp/out"),
      bash("rm -r -- /var/tmp/run-7"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\review-1"),
      pwsh("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\review-1\\tests"),
      pwsh("ri -Recurse C:\\Windows\\Temp\\build-7"),
      // The same through Cursor's Shell (labelled Bash), and on a POSIX shell, where each
      // target is one file name in the working directory once the backslashes are removed.
      bash("Remove-Item -Recurse -Force C:\\Users\\dev\\AppData\\Local\\Temp\\review-1"),
      bash("Remove-Item -Recurse -Force C:\\Windows\\Temp\\build-7 C:\\Windows\\Temp\\build-8"),
      bash("rm -rf C:\\Users\\dev\\AppData\\Local\\Temp\\review-1"),
    ],
  },
};
