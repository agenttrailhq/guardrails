import { QUOTED_MENTION, SHELL_AND_MCP } from "../../exemptions.js";
import { bash, mcp, mentions } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Recursive-force delete rooted at `/`.
 *
 * `rm -rf /` denies and `rm -rf ./node_modules` allows; that discrimination is the
 * whole point.
 *
 * Both `r` and `f` are required, in either order. `rm -f /tmp/app.pid` is a
 * single-file force delete of an absolute path, not a recursive wipe, and is not
 * matched.
 */
export const ddRmRfAbsolute: Rule = {
  id: "dd.rm-rf-absolute",
  category: "destructive-data",
  severity: "critical",
  defaultAction: "block",
  title: "rm -rf against an absolute path",
  description:
    'Recursive-force delete rooted at `/` rather than at a relative path. Deliberately does NOT fire on `rm -rf ./node_modules` or `rm -rf build`, which are safe and happen many times a day. Both the r and the f flag are required, so `rm -f /tmp/app.pid` is not blocked either. Known misses: the long forms (`rm --recursive --force /`), a quoted target (`rm -rf "/"`), and a variable target (`rm -rf $DIR`) whose value is only known at run time — for those, see require-approval-rm-rf, which holds them for approval instead. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: SHELL_AND_MCP,
        detail_matches: ["\\brm\\s+-[a-z]*r[a-z]*f\\s+/", "\\brm\\s+-[a-z]*f[a-z]*r\\s+/"],
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
      mcp({ command: "rm -rf /" }),
    ],
    allow: [
      ...mentions("rm -rf /"),
      bash("rm -rf ./node_modules"),
      bash("rm -rf build/"),
      bash("rm -f /tmp/app.pid"),
      bash("rm -rf $TMPDIR/scratch"),
      bash('wc -l < log; echo "--- rm -rf / ---"; grep -c x log'),
      mcp({ command: "rm -rf ./node_modules" }),
    ],
  },
};
