import {
  ARG_END,
  QUOTED_MENTION,
  RM_ARG_REST,
  RM_ARGS,
  RM_RECURSIVE,
  RM_WORD,
  SHELL_AND_MCP,
} from "../../exemptions.js";
import { bash, mcp, mentions } from "../../fixtures.js";
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
 */
export const ddRmRfAbsolute: Rule = {
  id: "dd.rm-rf-absolute",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  owasp: ["ASI02", "LLM03"],
  title: "rm -rf against an absolute path",
  description:
    'Recursive delete rooted at `/` rather than at a relative path, with or without the force flag. The recursive flag (`-r`, `-R`, a cluster such as `-rf` or `-Rv`, or `--recursive`) and the absolute target may sit anywhere among the arguments of one `rm`: split across arguments (`rm -r -f /srv`), after `--`, after a relative operand, or after the target, and a quoted target (`rm -rf "/srv"`) counts too. Deliberately does NOT fire on `rm -rf ./node_modules` or `rm -rf build`, which are safe and happen many times a day, or on `rm -f /tmp/app.pid`, which has no recursive flag. Known misses: a variable or `~` target (`rm -rf $DIR`) whose value is only known at run time — for those, see require-approval-rm-rf, which holds them for approval instead; an `rm` with more than twelve arguments before the flag or the target; a command continued onto the next line with a backslash; and a delete through `find -delete` or a file tool. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
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
    none_of: [...QUOTED_MENTION],
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
    ],
    allow: [
      ...mentions("rm -rf /"),
      ...mentions("rm -r -f /srv/data"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf build/"),
      bash("rm -f /tmp/app.pid"),
      bash("rm -rf $TMPDIR/scratch"),
      bash('wc -l < log; echo "--- rm -rf / ---"; grep -c x log'),
      bash("rm -r ./build"),
      bash("rm -v /tmp/a.log"),
      bash("rm -rf build 2> /dev/null"),
      bash("rm -rf build 2>/dev/null"),
      bash("rm -rf build && ls /"),
      bash("docker run --rm -v /srv:/data img cp -r /a /b"),
      mcp({ command: "rm -rf ./node_modules" }),
    ],
  },
};
