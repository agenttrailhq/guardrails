// cspell:words BEHAVIOUR EDITMSG
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Editing git's own bookkeeping rather than the files it tracks.
 *
 * Narrow on purpose: `.git/COMMIT_EDITMSG` and `.git/index` change constantly
 * during normal work, and a rule over all of `.git/**` would fire on ordinary
 * commits. What is listed here is the subset that changes BEHAVIOUR — the config,
 * the hooks, the refs, and HEAD.
 */
export const fsVcsInternals: Rule = {
  id: "fs.vcs-internals",
  category: "file-scope",
  severity: "high",
  defaultAction: "require_approval",
  title: "Editing git's internals directly",
  description:
    "Holds a file tool opening git's own bookkeeping — .git/config, .git/hooks/, .git/refs/, .git/HEAD, .git/info/exclude — where a change alters what future git commands do rather than what the repository contains. Deliberately NARROW: all of .git/** would include COMMIT_EDITMSG and the index, which change during every ordinary commit, so the rule would fire constantly and be switched off. It does NOT match .gitignore, .gitattributes or anything under .github/, which are tracked project files.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.git/config" },
      { kind: "execute_tool", file_glob: "**/.git/hooks/**" },
      { kind: "execute_tool", file_glob: "**/.git/refs/**" },
      { kind: "execute_tool", file_glob: "**/.git/HEAD" },
      { kind: "execute_tool", file_glob: "**/.git/info/exclude" },
    ],
  },
  fixtures: {
    block: [
      file(".git/config"),
      file(".git/hooks/pre-commit", "Write"),
      file(".git/refs/heads/main", "Write"),
      file(".git/info/exclude"),
    ],
    allow: [
      file(".gitignore"),
      file(".gitattributes"),
      file(".github/CODEOWNERS"),
      file("src/index.ts"),
    ],
  },
};
