// cspell:words basenc uudecode unxz unzstd gzcat bzcat xzcat zstdcat lz4cat bunzip zstd stdbuf nohup popen certutil cscript wscript frombase64string scriptblock MMIME bxxd doas decompressors zcat biex urandom norc lzcat pigz mksh setsid ionice

import { QUOTED_MENTION, SEP, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * A decoder word, then its decode flag later in the same segment. The flag is a lookahead, so
 * the text after the word is read once for the flag and once for the pipe, not once for every
 * pairing of the two, which keeps a long segment linear.
 */
const dec = (word: string, flag: string, span = 999): string =>
  `${word}(?=[^|;&\\n]{0,${span}}${flag})`;

/** Decoders and unpackers whose output is text that was hidden from every other guardrail. */
const B64_D = "\\s--?[a-z]{0,4}d";
const ZIP_D = "\\s-(?:[a-z]{0,3}d|-de|-un)";
const ZIP_CAT = "\\b(?:[gb]unzip2?|unxz|unzstd|(?:g?z|bz|xz|zstd|lz4)cat)\\b";
/** `tr` only as a ROT13 rotation; any other `tr` is ordinary text processing. */
const ROT = "\\btr\\s{1,4}[\"']?(?:a-z|a-za-z)[\"']?\\s{1,4}[\"']?n-za-m";

/**
 * Each decoder with up to `span` characters of its own arguments before the decode flag. A few
 * are split in two to keep each pattern within the length limit. ROT13 comes last.
 */
const decoders = (span = 999): string[] => [
  dec("\\bg?base(?:64|32)", B64_D, span),
  dec("\\bbasenc", B64_D, span),
  dec("\\bopenssl\\b", "\\s-d\\b", span),
  `(?:${dec("\\bxxd\\b", "\\s-[a-z]{0,3}r", span)}|\\buudecode\\b)`,
  ZIP_CAT,
  dec("\\b(?:gzip|bzip2)", ZIP_D, span),
  dec("\\b(?:xz|zstd)\\b", ZIP_D, span),
  ROT,
];

/** Perl, Ruby, Python, and Node or PHP one-liners that decode base64. */
const PR_D = "(?:decode_base64|unpack\\(?[\"']m)";
const PN_D = "(?:b64decode|base64[\"'_])";
const LANG = [
  dec("\\bperl", PR_D, 300),
  dec("\\bruby", PR_D, 300),
  dec("\\bpython[\\d.]{0,4}", PN_D, 300),
  dec("\\b(?:node|php)", PN_D, 300),
];

/**
 * One wrapper before the shell, by name or by path (`/usr/bin/env`), with up to six arguments
 * of its own: flags, a flag's value (`sudo -u root`), `VAR=value`, a duration (`timeout 5`), or
 * a chained wrapper (`sudo -E env -i nice -n 5`). The arguments stay on one line and in one
 * command: none holds a separator or a pipe.
 */
const WRAP =
  "(?:(?:\\S{0,40}/)?(?:sudo|doas|env|nice|time(?:out)?|command|exec|stdbuf|nohup)(?:[ \\t]+[^\\s;&|]{1,80}){0,6}[ \\t]+)?";

/**
 * The end of the shell's segment, after any blanks: a separator, a line break, a comment or a
 * redirect, or the quote that closes the string holding the command (`bash -c "… | sh"`, an MCP
 * tool's JSON input). A quote that opens more text (`python3 -c '…'`, `sh -c 'cat > f'`) is a
 * program argument, not an end.
 */
const SH_END = "\\s*(?:$|[;&|)\\n\\r#]|\\d?[<>]|[\"'](?![^\\s;&|)}]))";

/** Shells and interpreters, in families to keep each pattern within the length limit. */
const SHELLS = ["(?:ba|z|k|da)?sh", "python[\\d.]{0,4}", "(?:node|perl|ruby)", "(?:php|pwsh)"];

/**
 * `.` and `source` read a program from a pipe only through a stdin path, and run no wrapper:
 * they are shell builtins.
 */
const DOT = `(?:\\.|source)[ \\t]+/(?:dev/(?:stdin|fd/0)|proc/self/fd/0)${SH_END}`;

/**
 * A shell or interpreter reading its program from stdin: an optional wrapper and path, then
 * only flags (`-`, `-s`, `--`) or a stdin path (`/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`; any
 * other `/dev/` path reads nothing that runs)
 * before the end of the segment. A script argument (`x.py`, `-m json.tool`, `-e code`,
 * `-c cmd`) means it is not running the decoded text.
 */
const stdin = (shell: string): string =>
  `${WRAP}(?:\\S{0,40}/)?${shell}(?:\\s+(?:-|/dev/|/proc/)[a-z0/-]{0,12}){0,4}${SH_END}`;

/**
 * Text from the decoder up to the last pipe of the segment, `|&` included, then blanks. A line
 * break after a pipe continues the pipeline.
 */
const PIPE_INTO = "[^;&\\n]{0,999}\\|&?\\s*";

/**
 * A substitution handed to a shell (`sh -c`, `bash --norc -c --`), to `eval`, to a redirect or
 * a here-string (`<(…)`, `<<< "$(…)"`), or run in command position: at the start, or after a
 * separator, a line break, `{`, `!`, `then`, `do` or `else`. The scan after the opening reads
 * through up to two nested `$(` (`$(echo $(base64 -d f))`) but stops at a bare `(`, which is
 * itself a start, so a run of `(` or `$(` is read a bounded distance from each start.
 */
const SUBST =
  "(?:\\b(?:ba|z|k|da)?sh(?:\\s{1,4}-\\S{1,20}){0,4}\\s{1,4}|\\beval\\s{1,4}(?:--\\s{1,4})?|<\\s{0,4}|(?:^|[;&|(\\n{!]|\\b(?:then|do|else)\\s)\\s{0,4})[\"']?(?:\\$\\(|\\(|`)(?:[^()`]{0,99}\\$\\(){0,2}[^()`]{0,300}";

const DEC_WORD =
  "\\b(?:g?base(?:64|32)|basenc|openssl|xxd|uudecode|[gb]unzip2?|unxz|unzstd|(?:g?z|bz|xz|zstd|lz4)cat|gzip|bzip2|xz|zstd)\\b";
const SH_WORD = "\\b(?:(?:ba|z|k|da)?sh|python[\\d.]{0,4}|node|perl|ruby|php|pwsh)\\b";

/** Each decoder piped into each family of stdin readers, one pattern per pair (length limit). */
const piped = (list: readonly string[]): string[] =>
  list.flatMap((d) => [
    ...SHELLS.map((sh) => `${d}${PIPE_INTO}${stdin(sh)}`),
    `${d}${PIPE_INTO}${DOT}`,
  ]);

/**
 * Decoded or unpacked text run by a shell.
 *
 * Encoding a command hides it from every text guardrail: `echo <base64> | base64 -d | sh`
 * runs whatever the blob holds and no rule sees it. The shape turns up mostly in malicious
 * content (a compromised install script, instructions injected through a page the agent
 * read), and there is almost never a reason for an agent to run it. One cheap shape, held;
 * not a decoder-by-decoder chase.
 */
export const rceDecodeToShell: Rule = {
  id: "rce.decode-to-shell",
  category: "rce-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI04", "ASI05", "LLM04"],
  title: "Running decoded or unpacked text as a command",
  description:
    "Holds a command that decodes or unpacks text and runs it, because no other guardrail can see what the encoded text does. Decoders: `base64`/`base32`/`basenc` with a decode flag (`-d`, `-D`, `-di`, `-id`, `--decode`), `openssl … -d`, `xxd -r`, `uudecode`, the decompressors (`gunzip`, `zcat`, `bzcat`, `xzcat`, `zstdcat`, `gzip -d`, `--decompress`, `--uncompress`, …), a ROT13 `tr`, and Perl, Ruby, Python, Node or PHP one-liners that decode base64. A decoder's arguments and the stages after it are read up to 999 characters. Caught when the result is piped (`|` or `|&`, through any number of pipes, a line break after a pipe included) into a shell or interpreter that reads its program from stdin (no script argument, or `-`, `-s`, `--`, or a stdin path: `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`; `.` and `source` only with a stdin path and no wrapper, since they are builtins), after a wrapper by name or path (`sudo`, `doas`, `env`, `/usr/bin/env`, `nice`, `time`, `timeout`, `command`, `exec`, `stdbuf`, `nohup`) and up to six of its arguments on the same line and in the same command, with any blanks, and up to the end of the segment (a separator, a line break, `#` or a redirect); handed to `sh -c` with any flags before it (`bash --norc -c`, `sh -c --`), `eval`, `source <(…)`, a process substitution, a here-string (`<<< \"$(…)\"`) or command position as `$(…)` (at the start, or after a separator, a line break, `{`, `!`, `then`, `do` or `else`); or piped to `xargs` into a shell. Also: a Python, Node, Perl or Ruby one-liner that decodes and `exec`s or `eval`s, PowerShell `-EncodedCommand` (any prefix, any dash), `FromBase64String` with `iex` or `[scriptblock]::Create`, and `certutil -decode` followed by running a script in the same command. Not held: decoding to a file or into a reader (`base64 -d f > out.bin`, `| jq`, `| shasum`, `| grep`), into an interpreter that runs a script or a program given with `-c` or `-e` (`| python3 -m json.tool`, `| python3 parse.py`, `| python3 -c '…json.load(sys.stdin)'`, `| perl -ne '…'`), a plain `tr` or `rev`, encoding, and printing the decoded text. Held, not blocked: unpacking a script and running it is occasionally legitimate, and a person can see the command. Known misses: decoded text written to a file and run by a later command, a decoder nested four `$(` deep (`$(a $(b $(c $(base64 -d f))))`), decoding inside a script, `rev` or a non-rotation `tr` (a bracketed ROT13 `tr '[a-z]' '[n-za-m]'` too), other encodings and unpackers (`unzip -p`, `tar -xO`, `lzcat`, `lz4 -d`, `brotli -d`, `pigz -d`, `7z -so`, `gpg -d`, `printf %b`, `echo -e`), a decoder or shell word quoted or escaped (`| \"sh\"`, `| \\sh`, `| b''ash`) or held in a variable (`| $SHELL`), other shells and runners (`ash`, `mksh`, `fish`, `csh`, `busybox sh`, `setsid`, `ionice`, `unbuffer`, `builtin`, `chroot`, `script`, `parallel`, `tee >(sh)`), a wrapper with more than six arguments, a shell flag that takes a value (`bash -o posix`), a backslash-newline before a redirect after the shell, a stdin path other than fd 0 (`/dev/fd/3`) or followed by an argument, a positional argument after `--` (`bash -s -- arg`), a Python, Node or PHP one-liner with `;` inside its quotes, a `$(…)` after a wrapper (`sudo $(…)`) or held in a variable, a here-document that holds `$(…)` without a shell before it, PowerShell's decode and `iex` on separate lines, and anything a variable holds. Known over-matches: any other `/dev/` or `/proc/` path after the shell (`| sh /dev/null`), and a long flag that starts like `--d` (`base64 --add-padding`). This is one cheap shape; isolation at the operating-system level is the answer to encoded payloads in general. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone.",
  match: {
    any_of: [
      ...[0, 2, 4, 6].map((i) => ({
        kind: "execute_tool" as const,
        label: SHELL_AND_MCP,
        detail_matches: piped(decoders().slice(i, i + 2)),
      })),
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          ...LANG.map((d) => `${d}${PIPE_INTO}${stdin(SHELLS[0] ?? "sh")}`),
          ...LANG.map((d) => `${SUBST}${d}`),
        ],
      },
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          // A substitution is short, so its decoder's arguments are read up to 99 characters.
          ...decoders(99)
            .slice(0, 7)
            .map((d) => `${SUBST}${d}`),
          `${DEC_WORD}[^;&\\n]{0,300}\\|&?\\s{0,4}xargs\\b[^|;&\\n]{0,100}${SH_WORD}`,
          // A shell whose -c program is stdin itself: `| bash -c "$(cat)"`.
          `${DEC_WORD}[^;&\\n]{0,300}\\|&?\\s*${SH_WORD}(?:\\s+-[a-z]{1,4}){1,4}\\s+["']?\\$\\(cat\\)`,
        ],
      },
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          `\\b(?:python[\\d.]{0,4}|node|perl|ruby)\\s[^\\n]{0,300}(?:b64decode|decode_base64|["']base64["']|unpack\\(["']m)[^\\n]{0,300}\\b(?:exec|eval|system|popen|subprocess|spawn|Function)\\b`,
          `\\b(?:python[\\d.]{0,4}|node|perl|ruby)\\s[^\\n]{0,300}\\b(?:exec|eval|system|popen|Function)\\b[^\\n]{0,300}(?:b64decode|decode_base64|["']base64["'])`,
          `\\b(?:powershell|pwsh)(?:\\.exe)?\\b[^|;&\\n]{0,200}${SEP}[-/\\u2013\\u2014]e(?:c|n[a-z]{0,13})?(?:${SEP}|:)`,
          "frombase64string[^\\n]{0,300}(?:\\biex\\b|invoke-expression|scriptblock\\]::create)|(?:scriptblock\\]::create|invoke-expression|\\biex\\b)[^\\n]{0,300}frombase64string",
          "\\bcertutil\\b[^\\n]{0,200}\\s[-/]decode(?:hex)?\\b[^\\n]{0,300}(?:&|;|\\|\\|)[^\\n]{0,300}(?:\\.(?:bat|cmd|ps1|exe|vbs|js|sh)\\b|\\b(?:cmd|powershell|pwsh|cscript|wscript|bash|sh)\\b)",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("echo cm0gLXJmIC8K | base64 -d | sh"),
      bash("echo cm0gLXJmIC8K | base64 --decode | bash"),
      bash("echo cm0gLXJmIC8K | base64 -D | sh"),
      bash("base64 -d f |& bash"),
      bash("base64 -id f | sh"),
      bash("openssl enc -base64 -d -in x | bash"),
      bash("xxd -r -p x.hex | bash"),
      bash("zcat x.gz | /bin/bash"),
      bash("gzip -dc x.gz | sh"),
      bash("echo x | tr a-zA-Z n-za-mN-ZA-M | sh"),
      bash("echo x | base64 -d | gunzip | sh"),
      bash("echo x | base64 -d | python3 -"),
      bash("echo x | base64 -d | node"),
      // Wrappers before the shell, with their own arguments.
      bash("base64 -d f | env bash"),
      bash("base64 -d f | env -i X=1 bash -s"),
      bash("base64 -d f | sudo -E bash -"),
      bash("echo x | base64 -d | nice bash"),
      bash("echo x | base64 -d | nice -n 10 bash"),
      bash("echo x | base64 -d | timeout 5 sh"),
      bash("echo x | base64 -d | command sh"),
      bash("echo x | base64 -d | doas sh"),
      bash("echo x | base64 -d | exec bash"),
      bash("echo x | base64 -d | stdbuf -oL bash"),
      bash("echo x | base64 -d | sudo -u root sh"),
      bash("echo x | base64 -d | doas -u root sh"),
      bash("echo x | base64 -d | nohup bash"),
      bash("echo x | base64 -d | sudo -E env -i nice -n 5 bash"),
      // The segment ends at a line break, a comment or a redirect.
      bash("base64 -d f | sh\necho done"),
      bash("base64 -d f | sh\r\necho done"),
      bash("base64 -d f | sh # run it"),
      bash("base64 -d f | sh 2>&1"),
      bash("base64 -d f | sh </dev/null"),
      bash("base64 -d f | bash > out.log"),
      // Any number of blanks or tabs around the shell, and a line break after the pipe.
      bash("base64 -d f | sh     "),
      bash("base64 -d f |\t\t\t\t\tsh"),
      bash(`base64 -d x |${" ".repeat(8000)}sh`),
      bash("base64 -d f |\n  sh"),
      // Long arguments, a long middle stage and many pipes.
      bash(`base64 -d /tmp/${"a".repeat(100)} | sh`),
      bash(`base64 -d f | grep -v ${"x".repeat(100)} | sh`),
      bash(`base64 ${"-w0 ".repeat(30)}-d f | sh`),
      bash(`xxd -p ${"-c 256 ".repeat(10)}-r f | sh`),
      bash(`echo x | base64 -d${" | cat".repeat(20)} | sh`),
      // The shell reading its program from a stdin path, and a wrapper by path or `time`.
      bash("base64 -d f | sh /dev/stdin"),
      bash("base64 -d f | bash /dev/fd/0"),
      bash("base64 -d f | bash /proc/self/fd/0"),
      bash("base64 -d f | python3 /dev/stdin"),
      bash("base64 -d f | . /dev/stdin"),
      bash("base64 -d f | source /dev/stdin"),
      bash("base64 -d f | /usr/bin/env sh"),
      bash("base64 -d f | /usr/bin/sudo sh"),
      bash("base64 -d f | time sh"),
      // The quote that closes the string holding the command ends the segment.
      bash('bash -c "base64 -d f | sh"'),
      bash("sh -c 'zcat x.gz | bash -s'"),
      // Decoder spellings.
      bash("cat f | base64 -di | sh"),
      bash("cat f | base64 --d | sh"),
      bash("cat f | base32 -d | sh"),
      bash("cat f | gzip --decompress -c | sh"),
      bash("cat f | gzip --uncompress | sh"),
      bash("cat f | xz --decompress | sh"),
      bash("cat f | zstd --decompress | sh"),
      bash("cat f | bzip2 --decompress | sh"),
      // A substitution, xargs, a here-string.
      bash('sh -c "$(echo x | base64 -d)"'),
      bash('bash -lc "$(base64 -d f)"'),
      bash('sh -c "`echo x | base64 -d`"'),
      bash("bash <(echo x | base64 -d)"),
      bash('eval "$(echo x | base64 -d)"'),
      bash('bash <<< "$(echo x | base64 -d)"'),
      bash("base64 -d f | xargs bash -c"),
      bash('base64 -d f | bash -c "$(cat)"'),
      // More flags before -c, eval --, command position after a line break, then, {, or !, and a
      // here-string with a blank after it.
      bash('bash --norc -c "$(base64 -d f)"'),
      bash('bash -e -c "$(base64 -d f)"'),
      bash('sh -c -- "$(base64 -d f)"'),
      bash('eval -- "$(base64 -d f)"'),
      bash("echo hi\n$(base64 -d f)"),
      bash("if :; then $(base64 -d f); fi"),
      bash("{ $(base64 -d f); }"),
      bash("! $(base64 -d f)"),
      bash('sh <<< "$(xxd -r -p f)"'),
      bash('sh <<< "$(zcat x.gz)"'),
      bash("bash <<EOF\n$(base64 -d f)\nEOF"),
      // Decoders in an interpreter.
      bash("perl -MMIME::Base64 -e 'print decode_base64($x)' | sh"),
      bash("node -e \"process.stdout.write(Buffer.from(x,'base64'))\" | sh"),
      bash("python3 -c \"exec(__import__('base64').b64decode('eA=='))\""),
      bash("python3 -c \"import base64,os;os.system(base64.b64decode('eA=='))\""),
      bash("node -e \"eval(Buffer.from('eA==','base64').toString())\""),
      // PowerShell and Windows.
      pwsh("powershell -enc ZQBjAGgAbwA="),
      pwsh("pwsh -EncodedCommand ZQBjAGgAbwA="),
      pwsh("pwsh –EncodedCommand ZQBjAGgAbwA="),
      pwsh("powershell.exe -e ZQBjAGgAbwA="),
      pwsh(
        "[scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('eA==')))",
      ),
      bash("certutil -decode a.b64 a.bat & a.bat"),
      mcp({ command: "echo x | base64 -d | sh" }),
    ],
    allow: [
      ...mentions("echo x | base64 -d | sh"),
      bash("echo x | base64 -d > out.bin"),
      bash("base64 -d <<< eA== | jq ."),
      bash("base64 -d secret.b64 | shasum -a 256"),
      bash("cat /dev/urandom | head -c 16 | base64"),
      bash("gunzip -c logs.gz | grep ERROR"),
      bash("echo $JWT | base64 -d | python3 -m json.tool"),
      bash("zcat x.gz | python3 parse.py"),
      bash("zcat x.gz | nice python3 parse.py"),
      bash("base64 -d f | sh ./run.sh"),
      bash("base64 -d f | bash /tmp/x.sh"),
      bash("base64 -d f | grep -c sh"),
      bash("base64 -w0 f | sh"),
      // A program given with -c or -e reads stdin as data, not as its program.
      bash("base64 -d <<< \"$P\" | python3 -c 'import json,sys; print(json.load(sys.stdin))'"),
      bash(
        'echo $JWT | cut -d. -f2 | base64 -d | python3 -c "import sys,json;print(json.load(sys.stdin))"',
      ),
      bash("base64 -d f | node -e 'process.stdin.pipe(process.stdout)'"),
      bash("zcat x.gz | perl -ne 'print if /ERR/'"),
      bash("zcat x.gz | ruby -e 'puts STDIN.read.size'"),
      bash("base64 -d f | sh -c 'cat > out.bin'"),
      // A wrapper's arguments end at a separator, a pipe or a line break, and a bare `.` is a path.
      bash("zcat dump.gz | sudo tar -x -C ."),
      bash("gunzip -c x.tgz | nice tar x -C ."),
      bash("zcat a.gz | env > e.txt; git add ."),
      bash("zcat a.gz | sudo tee out.txt; git add ."),
      bash("zcat a.gz | nice -n 19 python3 analyze.py ."),
      bash("gunzip -c a.gz | time wc -l; ls ."),
      bash("base64 -d f | env jq ."),
      bash("base64 -d f | command jq ."),
      bash("zcat dump.sql.gz | sudo -u postgres psql\nls ."),
      bash("gunzip -c a.gz | sudo tee /etc/x >/dev/null\nsh"),
      bash("zcat a.gz | nice grep x\npython3"),
      bash("base64 -d f | python3 parse.py # x"),
      bash("base64 -d f > out.sh # save for review"),
      bash("cat a.csv | tr , '\\t' | python3 x.py"),
      bash("git rev-parse HEAD | python3 x.py"),
      bash("tr -d '\\r' < in.sh > out.sh"),
      bash("tar -xzf x.tgz && sh ./configure"),
      bash("python3 -c \"import base64;print(base64.b64decode('eA=='))\""),
      pwsh("powershell -ExecutionPolicy Bypass -File x.ps1"),
      pwsh("pwsh -NoProfile -Command Get-ChildItem"),
    ],
  },
};
