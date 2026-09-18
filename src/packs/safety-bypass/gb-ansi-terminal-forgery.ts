// cspell:words OSC colour colourised mred neutralise setaf terminfo tput
import {
  GIT_TEXT_MENTION,
  HTTP_BODY_MENTION,
  SEARCH_MENTION,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mentionInCommit, mentionInPost, mentionInSearch, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Printing raw terminal control sequences.
 *
 * OWASP LLM10:2026 names the sink in its own words: "terminal, log, or IDE sinks that render model
 * output without neutralizing control characters such as ANSI escape sequences". An `echo`/`printf`
 * emitting a raw escape can move the cursor, rewrite the title bar, or plant a clickable hyperlink —
 * forging what a human reads back from the terminal.
 */
export const gbAnsiTerminalForgery: Rule = {
  id: "gb.ansi-terminal-forgery",
  category: "safety-bypass",
  severity: "medium",
  defaultAction: "warn",
  title: "Emitting raw terminal control sequences",
  description:
    "Warns when `echo` or `printf` emits a raw terminal control sequence — the escape introducer `\\x1b`, `\\033` or `\\e` followed by `[` (a CSI: cursor moves, screen clears, colour) or `]` (an OSC: `]0;` sets the window title, `]8;;` plants a clickable hyperlink). Rendered into a terminal, log or IDE that does not neutralise them, these forge what a human reads back. This is a broad `warn` on purpose: a colourised build line trips it too, and that is an acceptable cost for a warning. Because its own trigger is an `echo`/`printf`, the `echo` quoted-MENTION carrier is NOT exempt here — an `echo` that prints an escape is exactly the case — while a search, a `git commit -m` message and a `curl --data` body that only name one are left alone. Matches the escape written as a backslash sequence in the command text. MISSES a raw ESC byte pasted literally, a sequence printed by a compiled program or a script file rather than an inline `echo`/`printf`, and `tput`, which reads terminfo and emits nothing literal in the command. The exemption holds only while every shell metacharacter stays inside the quotes.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: ["\\b(?:echo|printf)\\b[^|;&]*(?:\\\\x1b|\\\\033|\\\\e)[[\\]]"],
      },
    ],
    none_of: [SEARCH_MENTION, GIT_TEXT_MENTION, HTTP_BODY_MENTION],
  },
  fixtures: {
    block: [
      bash("printf '\\033]0;you are safe\\007'"),
      bash("printf '\\x1b]8;;https://evil.example\\x1b\\\\click here\\x1b]8;;\\x1b\\\\'"),
      bash("echo -e '\\e[2J\\e[H all tests passed'"),
      bash("echo -e '\\033[1000D\\033[K fake@prompt$ '"),
      pwsh("echo '\\033[31mred\\033[0m'"),
    ],
    allow: [
      mentionInCommit("printf \\033]0;title\\007"),
      mentionInSearch("printf \\033]0;title\\007"),
      mentionInPost("printf \\033]0;title\\007"),
      bash("echo 'hello world'"),
      bash('echo "Deploy complete"'),
      bash("printf '%s\\n' \"$VERSION\""),
      bash("echo -e 'line1\\nline2'"),
      bash("tput setaf 1"),
    ],
  },
};
