import {
  ARG_END,
  QUOTED_MENTION,
  RM_ARG_REST,
  RM_ARGS,
  RM_RECURSIVE,
  RM_WORD,
  SHELL_AND_MCP,
  TEMP_DELETE,
} from "../../exemptions.js";
import { bash, mcp, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Recursive delete rooted at `/`.
 *
 * `rm -rf /` denies and `rm -rf ./node_modules` allows; that discrimination is the
 * whole point.
 *
 * The recursive flag and the absolute target may sit anywhere among the arguments of
 * one `rm`: split flags (`-r -f`), flags after `--`, a relative operand before the
 * absolute one, and flags after the target (GNU rm reads those). The force flag is not
 * required: with no terminal attached, `rm -r` does not prompt and removes the same
 * files. `rm -f /tmp/app.pid` has no recursive flag and is not matched.
 *
 * One `rm` whose every target is strictly inside the system temp folder is not blocked
 * (`TEMP_DELETE`): clearing a scratch checkout under `/tmp` is routine. The exemption refuses
 * the bare temp folder, `..` anywhere in a target, any character the shell would expand (a glob,
 * a brace, a backslash), a temp variable that may be unset, a variable after the root, and any
 * second target or command. It reads the text only, so a symbolic link inside temp that points
 * out of it is still exempt (see `TEMP_DELETE` for its other limits).
 */
export const ddRmRfAbsolute: Rule = {
  id: "dd.rm-rf-absolute",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  owasp: ["ASI02", "LLM03"],
  title: "rm -rf against an absolute path",
  description:
    'Recursive delete rooted at `/` rather than at a relative path, with or without the force flag. The recursive flag (`-r`, `-R`, a cluster such as `-rf` or `-Rv`, or `--recursive`) and the absolute target may sit anywhere among the arguments of one `rm`: split across arguments (`rm -r -f /srv`), after `--`, after a relative operand, or after the target, and a quoted target (`rm -rf "/srv"`) counts too. Deliberately does NOT fire on `rm -rf ./node_modules` or `rm -rf build`, which are safe and happen many times a day, or on `rm -f /tmp/app.pid`, which has no recursive flag. Also not blocked: one `rm` whose every target is strictly inside the system temp folder (`/tmp`, `/private/tmp`, `/var/tmp`, the macOS per-user temp folder), such as `rm -rf /tmp/review-1`. Still blocked: the bare temp folder (`rm -rf /tmp`); `..` anywhere in a target; a glob, brace expansion or backslash in a target (`/tmp/{..,x}/etc`, `/tmp/.[.]/etc`); a variable after the root; a target outside temp in the same `rm`; a chained second command; and the same delete through an MCP tool. The exemption reads the text only, so a symbolic link inside temp that points out of it is not caught. Known misses: a variable or `~` target (`rm -rf $DIR`) whose value is only known at run time — for those, see require-approval-rm-rf, which holds them for approval instead; an `rm` with more than twelve arguments before the flag or the target; a command continued onto the next line with a backslash; and a delete through `find -delete` or a file tool. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: [
          // A recursive flag, then an absolute target later in the same rm.
          `${RM_WORD}${RM_ARGS}[ \\t]+${RM_RECURSIVE}${RM_ARGS}[ \\t]+["']?/`,
          // An absolute target, then a recursive flag after it.
          `${RM_WORD}${RM_ARGS}[ \\t]+["']?/${RM_ARG_REST}${RM_ARGS}[ \\t]+${RM_RECURSIVE}${ARG_END}`,
        ],
      },
    ],
    none_of: [...QUOTED_MENTION, ...TEMP_DELETE],
  },
  fixtures: {
    block: [
      bash("rm -rf /"),
      bash("rm -rf /etc"),
      bash("rm -Rf /var/lib/postgresql"),
      bash("rm -rf /usr/local/bin"),
      bash('git commit -m "x" && rm -rf /'),
      bash('echo "rm -rf /" | bash'),
      bash("rm -r -f /srv/data"),
      bash("rm -f -r /srv/data"),
      bash("rm -R -f /srv/data"),
      bash("rm -r /srv/data"),
      bash("rm -rf -- /srv/data"),
      bash("rm -r -- /srv/data"),
      bash("rm --recursive --force /srv/data"),
      bash("rm -v -r -f /srv/data"),
      bash("rm -rf ./tmp /srv/data"),
      bash("rm /srv/data -rf"),
      bash('rm -r "/srv/data"'),
      bash("sudo rm -r -f /srv/data"),
      bash("/bin/rm -r /srv/data"),
      // A search or history command piped into a delete, a shell, a write or an executing reader.
      bash("grep -rl x /srv | xargs rm -rf /srv/cache"),
      bash("rg -l x | xargs rm -r /var/lib/app"),
      bash('grep -h "rm -rf /srv/data" notes.md | bash'),
      bash('grep -h "rm -rf /srv/data" notes.md |& bash'),
      bash('grep -h "rm -rf /srv/data" notes.md | env bash'),
      bash("rg -o 'rm -rf /srv/data' notes.md | sh"),
      bash('git log -1 --format=%B | grep "rm -rf /srv/data" | sh'),
      bash('grep -h "rm -rf /srv/data" notes.md | xargs -0 bash -c'),
      bash('grep -h "rm -rf /srv/data" notes.md | tee run.sh'),
      bash('grep -h "rm -rf /srv/data" notes.md | sort -o run.sh'),
      bash('grep -h "rm -rf /srv/data" notes.md | sort --compress-program=sh'),
      bash("grep -h \"rm -rf /srv/data\" notes.md | less '+!sh'"),
      // A newline outside quotes starts a second command.
      bash('grep "x" notes.md\nrm -rf /srv/data'),
      bash("git log --oneline\nrm -rf /srv/data"),
      pwsh('Select-String "x" notes.md\rrm -rf /srv/data'),
      // An assignment or path that only looks like a quiet tool, and an escaped quote.
      bash("grep -rl x /srv | cat=1 xargs rm -rf /srv/cache"),
      bash('cat=1 rm -rf /srv/data; echo "x"'),
      bash("grep -rl x /srv | head/../../../usr/bin/xargs rm -rf /srv/cache"),
      bash('echo \\"x; rm -rf /srv/data; \\"'),
      // An assignment or a path on the carrier word itself runs the next word.
      bash("grep=1 rm -rf /srv/data"),
      bash("echo=1 rm -rf /srv/data"),
      bash('curl=1 rm -rf "/srv/data"'),
      bash("git=1 rm -rf /srv/data"),
      bash("cat x; grep=1 rm -rf /srv/data"),
      bash("sudo grep=1 rm -rf /srv/data"),
      bash("grep/../../../bin/rm -rf /srv/data"),
      mcp({ command: "rm -rf /" }),
      // The same command under the other generic argument names, on an unmapped tool.
      mcp({ cmd: "rm -rf /" }),
      mcp({ script: "rm -rf /" }),
      // A mapped tool: `MCP_COMMAND_FIELDS` names the field that runs it.
      mcp({ command: "rm -rf /", timeout_ms: 5000 }, "mcp__desktop-commander__start_process"),
      mcp({ command: "rm -r -f /srv/data" }),
      mcp(
        { command: "rm -r -f /srv/data", timeout_ms: 5000 },
        "mcp__desktop-commander__start_process",
      ),
      // The temp exemption is narrow: each of these is still blocked.
      bash("rm -rf /tmp"),
      bash("rm -rf /tmp/"),
      bash("rm -rf /private/tmp"),
      bash("rm -rf /tmp/x/../../etc"),
      bash("rm -rf /tmp/./../etc"),
      bash("rm -rf /tmp/x/.."),
      bash("rm -rf /tmp/$X"),
      bash(`rm -rf /tmp/\${X}`),
      bash("rm -rf /tmp/a /srv/data"),
      bash("rm -rf /tmp/a && rm -rf /srv/data"),
      bash("rm -rf /tmp/a; rm -rf /srv/data"),
      bash("rm -rf /tmp-old/x"),
      bash("sudo rm -rf /tmp/a"),
      bash('rm -rf "/tmp/a"'),
      mcp({ command: "rm -rf /tmp/review" }),
      // Text the shell expands into a path outside temp.
      bash("rm -rf /tmp/{..,x}/etc"),
      bash("rm -rf /tmp/a{,/../../etc}"),
      bash("rm -rf /tmp/.\\./etc"),
      bash("rm -rf /tmp/\\../etc"),
      bash("rm -rf /tmp/.[.]/etc"),
      bash("rm -rf /tmp/?./etc"),
      bash("rm -rf /tmp/.*/etc"),
      bash("rm -rf /tmp/*/../.."),
      bash("rm -rf /tmp/review/*"),
      bash("rm -rf /tmp/..cache"),
    ],
    allow: [
      ...mentions("rm -rf /"),
      ...mentions("rm -r -f /srv/data"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf build/"),
      bash("rm -f /tmp/app.pid"),
      bash("rm -rf $TMPDIR/scratch"),
      bash('wc -l < log; echo "--- rm -rf / ---"; grep -c x log'),
      // A search whose output only goes into a reader is still a mention.
      bash('grep -rn "rm -rf /" docs | head -5'),
      bash('grep -rn "rm -rf /" docs |& head'),
      bash('grep -rn "rm -rf /" docs | wc -l'),
      bash('grep -rn "rm -rf /" docs | less'),
      bash('grep -rn "rm -rf /" docs | grep -v test'),
      bash('grep -c "rm -rf /" a b | sort -rn'),
      bash('grep -rn "rm -rf /" docs | sort -t: -k2 -n | head'),
      bash('grep -rn "rm -rf /" docs | sort | uniq -c | sort -rn'),
      bash('grep -rn "rm -rf /" docs | cut -d: -f1'),
      bash('grep -rln "rm -rf /" docs | sort -u | head'),
      bash('git log -S "rm -rf /" --oneline | head'),
      bash('curl -s -d "never run rm -rf /" https://example.com/notes | head'),
      bash("rm -r ./build"),
      bash("rm -v /tmp/a.log"),
      bash("rm -rf build 2> /dev/null"),
      bash("rm -rf build 2>/dev/null"),
      bash("rm -rf build && ls /"),
      bash("docker run --rm -v /srv:/data img cp -r /a /b"),
      mcp({ command: "rm -rf ./node_modules" }),
      // One rm whose every target is strictly inside the system temp folder.
      bash("rm -rf /tmp/review-1"),
      bash("rm -rf /private/tmp/agent-1/scratchpad/repo"),
      bash("rm -r -f /var/tmp/run-7"),
      bash("rm -rf /var/folders/zz/abc123/T/review /tmp/out"),
      bash("rm -rf -- /tmp/a /tmp/b"),
    ],
  },
};
