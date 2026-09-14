import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Writing outside the project, in the only sense the guard can express.
 *
 * The obvious rule — "the agent wrote outside the project" — CANNOT BE WRITTEN.
 * `MappedCall.args` carries exactly `full_command` and `file_path`, and the
 * `PreToolUse` payload carries exactly `tool_name` and `tool_input`: there is no
 * cwd and no project root anywhere in what the guard sees, so "outside the
 * project" has nothing to compare against and would match everything or nothing.
 * This rule is therefore bounded to well-known ABSOLUTE paths, permanently, and
 * says so in its own description.
 */
export const fsSystemPaths: Rule = {
  id: "fs.system-paths",
  category: "file-scope",
  severity: "high",
  defaultAction: "require_approval",
  title: "Writing to a system directory",
  description:
    "Holds a file tool opening a path under a system directory — /etc, /bin, /sbin, /usr/bin, /usr/local/bin, /boot, /System, /Library/LaunchDaemons, or Windows/System32. HONEST CEILING: this is a list of well-known ABSOLUTE paths and it cannot be anything else. No working directory and no project root reaches the guard, so the rule you would actually want — 'the agent wrote outside the project' — is inexpressible, and would match everything or nothing. It therefore MISSES a write anywhere else outside your repository, including another project on the same machine.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "/etc/**" },
      { kind: "execute_tool", file_glob: "/bin/**" },
      { kind: "execute_tool", file_glob: "/sbin/**" },
      { kind: "execute_tool", file_glob: "/usr/bin/**" },
      { kind: "execute_tool", file_glob: "/usr/local/bin/**" },
      { kind: "execute_tool", file_glob: "/boot/**" },
      { kind: "execute_tool", file_glob: "/System/**" },
      { kind: "execute_tool", file_glob: "/Library/LaunchDaemons/**" },
      { kind: "execute_tool", file_glob: "**/Windows/System32/**" },
    ],
  },
  fixtures: {
    block: [
      file("/etc/hosts", "Write"),
      file("/usr/local/bin/app", "Write"),
      file("/Library/LaunchDaemons/com.example.plist", "Write"),
      file("C:/Windows/System32/drivers/etc/hosts", "Write"),
    ],
    allow: [
      file("src/index.ts"),
      file("/home/dev/project/src/main.rs"),
      file("/tmp/scratch.txt", "Write"),
      file("docs/etc-notes.md"),
    ],
  },
};
