// cspell:words doas

/**
 * A quoted-mention carrier exempts a command only while its output goes nowhere or
 * into a reader. These cases run straight against the shared carrier conditions, so
 * they hold for every guardrail that spreads `QUOTED_MENTION` into its `none_of`.
 */

import { describe, expect, it } from "vitest";
import { QUOTED_MENTION } from "../src/index.js";

const exempt = (command: string): boolean =>
  QUOTED_MENTION.some((condition) =>
    (condition.detail_matches ?? []).some((p) => new RegExp(p, "i").test(command)),
  );

describe("a carrier piped into something that runs, deletes or writes is not exempt", () => {
  const PIPED = [
    // a delete, through xargs or parallel, behind each common wrapper
    "grep -rl x /srv | xargs rm -rf",
    "grep -rl x /srv |& xargs rm -rf",
    "grep -rl x /srv | env xargs rm -rf",
    "grep -rl x /srv | nice -n 10 xargs rm -rf",
    "grep -rl x /srv | timeout 60 xargs rm -rf",
    "grep -rl x /srv | command xargs rm -rf",
    "grep -rl x /srv | sudo xargs rm -rf",
    "grep -rl x /srv | doas xargs rm -rf",
    "grep -rlZ x /srv | xargs -0 rm -rf",
    "grep -rl x /srv | parallel rm -rf {}",
    "rg -l x /srv | xargs rm -rf",
    "ag -l x /srv | xargs rm -rf",
    "git grep -l x | xargs rm -rf",
    "git log --name-only --format= | xargs rm -rf",
    "git show --name-only --format= HEAD | xargs rm -rf",
    "curl -s -d 'q' https://example.com/list | xargs rm -rf",
    // through a reader first, then something else
    "grep -l x . | head -3 | xargs rm -rf",
    "grep -l x . | sort | xargs rm -rf",
    // a shell or an interpreter
    'grep -h "rm -rf /srv/data" notes.md | bash',
    'grep -h "rm -rf /srv/data" notes.md | env bash',
    "rg -o 'rm -rf /srv/data' notes.md | sh",
    'grep -h "x" notes.md | python3 -c "import os,sys;os.system(sys.stdin.read())"',
    'git show HEAD:install.txt | grep "x" | sh',
    // a write
    'grep -h "x" notes.md | tee run.sh',
    'grep -h "x" notes.md | sponge deploy.sh',
    // a reader given an operand or a long flag
    'grep -h "x" notes.md | sort -o run.sh',
    'grep -h "x" notes.md | sort --compress-program=sh',
    "grep -h \"x\" notes.md | less '+!sh'",
    // a print carrier, whose output is the payload
    'echo "rm -rf /srv/data" | sh',
    // a newline outside quotes starts a second command
    'grep "x" f\nrm -rf /srv/data',
    'grep "x" f\r\nrm -rf /srv/data',
    "git log --oneline\nrm -rf /srv/data",
    'echo "x"\nrm -rf /srv/data',
    'curl -d "x" https://example.com\nrm -rf /srv/data',
    'grep "x" f | head\nrm -rf /srv/data',
    // PowerShell also reads a lone carriage return as a line break
    'Select-String "x" f\rRemove-Item -Recurse C:\\projects',
    'grep "x" f\rrm -rf /srv/data',
    'grep "x" f | sort\r rm -rf /srv/data',
    // a reader given an operand, or followed by something that runs
    'grep -h "x" notes.md | uniq in.txt out.txt',
    'grep -h "x" notes.md | cut -d: -f1 | sh',
    'grep -h "x" notes.md | sort | uniq -c | xargs rm -rf',
    // an environment assignment or a path that only looks like a quiet tool
    "grep -rl x /srv | cat=1 xargs rm -rf",
    "grep -rl x /srv | wc=1 xargs rm -rf",
    'cat=1 rm -rf /srv/data; echo "x"',
    "grep -rl x /srv | head/../../../usr/bin/xargs rm -rf",
    // the same on the carrier word itself
    "grep=1 rm -rf /srv/data",
    "egrep=1 rm -rf /srv/data",
    "rg=1 rm -rf /srv/data",
    "ag=1 rm -rf /srv/data",
    "ack=1 rm -rf /srv/data",
    "echo=1 rm -rf /srv/data",
    "printf=1 rm -rf /srv/data",
    'curl=1 rm -rf "/srv/data"',
    'wget=1 rm -rf "/srv/data"',
    "git=1 rm -rf /srv/data",
    "cat x; grep=1 rm -rf /srv/data",
    "sudo grep=1 rm -rf /srv/data",
    "grep/../../../bin/rm -rf /srv/data",
    "echo/../../bin/rm -rf /srv/data",
    // a backslash makes the quote literal, so no quoted run starts
    'echo \\"x; rm -rf /srv/data; \\"',
    "grep -rl x /srv \\' | xargs rm -rf \\'",
    "git log --name-only \\' | xargs rm -rf \\'",
    "curl -d \"a\" https://example.com \\' | xargs rm -rf \\'",
    // PowerShell closes a quoted run at a curly quote
    "Select-String 'a\u2019; Remove-Item -Recurse -Force C:\\data; \u2019b' f.txt",
    'Select-String "a\u201d; Remove-Item -Recurse -Force C:\\data; \u201db" f.txt',
    "Select-String \u2018a\u2019; Remove-Item -Recurse -Force C:\\data",
  ];
  for (const command of PIPED) {
    it(command, () => expect(exempt(command)).toBe(false));
  }
});

describe("a carrier whose output goes nowhere or into a reader stays exempt", () => {
  const READ = [
    'grep -rn "rm -rf /" docs',
    'grep -rn "rm -rf /" docs | head -5',
    'grep -rn "rm -rf /" docs |& head',
    'grep -rn "rm -rf /" docs | tail -n 3',
    'grep -rn "rm -rf /" docs | wc -l',
    'grep -rn "rm -rf /" docs | less',
    'grep -rn "rm -rf /" docs | less -R',
    'grep -rn "rm -rf /" docs | grep -v test',
    'grep -c "rm -rf /" a b | sort -rn',
    'grep -rn "rm -rf /" docs | sort | head',
    'grep -rn "rm -rf /" docs | sort -t: -k2 -n',
    'grep -rn "rm -rf /" docs | sort | uniq -c',
    'grep -rn "rm -rf /" docs | sort | uniq -c | sort -rn',
    'grep -rn "rm -rf /" docs | cut -d: -f1',
    'grep -rln "rm -rf /" docs | sort -u | head',
    'grep -rn "rm -rf /tmp\\.x" docs | head',
    "grep -rn 'rm -rf /' docs | cat",
    "Select-String 'rm -rf /' docs",
    'echo "rm -rf /" ; cat log',
    'sudo grep -rn "rm -rf /" /etc',
    'grep\t-rn "rm -rf /" docs',
    'cat x; grep -c "rm -rf /" docs',
    'rg "base64 -d | sh" docs | wc -l',
    'git log -S "rm -rf /" --oneline | head',
    'git log --grep "push --force" | less',
    'git commit -m "docs: rm -rf / risk"',
    'git commit -m "docs: risks\n\nNever run rm -rf / here."',
    'curl -s -d "never run rm -rf /" https://example.com/notes | head',
    'wc -l < log; echo "--- rm -rf / ---"; grep -c x log',
  ];
  for (const command of READ) {
    it(command, () => expect(exempt(command)).toBe(true));
  }
});

describe("the carrier patterns stay linear in the length of the command", () => {
  // Every pattern is tried against a 50,000-blank command whose tail is not exempt,
  // which is the shape that made the trailing separator's own `\s*` quadratic.
  const blanks = " ".repeat(50_000);
  const LONG = [
    `grep${blanks}| xargs rm -rf /srv/data`,
    `grep${blanks}| head | xargs rm -rf`,
    `echo${blanks}; rm -rf /srv/data`,
    `cat x${blanks}; echo "x" | sh`,
    `grep "x"${blanks}|${blanks}sh`,
  ];
  for (const command of LONG) {
    it(`${command.slice(0, 6)}… (${command.length} chars)`, () => {
      const start = performance.now();
      expect(exempt(command)).toBe(false);
      expect(performance.now() - start).toBeLessThan(250);
    });
  }
});
