// cspell:words chmods

import { QUOTED_MENTION } from "../../exemptions.js";
import { bash, mentions, pwsh } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * `chmod 777` is the reflex fix for a permissions error and it is almost never
 * the right one — it makes the file writable by every account on the machine,
 * including whatever the next dependency install runs as.
 *
 * The `allow` fixtures are the ordinary chmods that sit right beside it.
 */
export const psPermissionWiden: Rule = {
  id: "ps.permission-widen",
  category: "privilege-supply-chain",
  severity: "high",
  defaultAction: "require_approval",
  title: "Making a file writable by everyone",
  description:
    'Holds a permission change that opens a file or directory to every account on the machine — `chmod 777`, `chmod a+rwx`, a setuid bit, or an icacls grant of full control to Everyone. It is the reflex fix for a permissions error and almost never the right one. The ordinary chmods that sit beside it are deliberately NOT matched: `chmod +x`, `chmod 644`, `chmod 755`. It cannot see WHAT is being widened, only that it is. A quoted MENTION is not a use: a search, a `git commit -m` message, an `echo` or a `curl --data` body that only names this command is left alone. That holds only while every shell metacharacter stays inside the quotes, so `git commit -m "x" && …` is still caught; and the carrier must be the first word, so `sudo grep …` is not exempt.',
  match: {
    any_of: [
      {
        kind: "execute_tool",
        label: "{Bash,PowerShell}",
        detail_matches: [
          "\\bchmod\\s+(-[a-z]+\\s+)?[0-7]?777\\b",
          "\\bchmod\\s+(-[a-z]+\\s+)?a\\+rwx\\b",
          "\\bchmod\\s+(-[a-z]+\\s+)?[ug]\\+s\\b",
          "\\bicacls\\b[^|;&]*/grant\\b[^|;&]*(everyone|users)[^|;&]*:\\(?f\\)?",
        ],
      },
    ],
    none_of: [...QUOTED_MENTION],
  },
  fixtures: {
    block: [
      bash("chmod 777 /var/www"),
      bash("chmod -R 777 uploads"),
      bash("chmod a+rwx deploy.sh"),
      pwsh("icacls C:\\app /grant Everyone:(F)"),
    ],
    allow: [
      ...mentions("chmod 777 /var/www"),
      bash("chmod +x scripts/build.sh"),
      bash("chmod 644 config.yml"),
      bash("chmod 755 bin/tool"),
      bash("chmod -R 750 /var/www"),
    ],
  },
};
