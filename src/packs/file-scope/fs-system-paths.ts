// cspell:words PROGRA
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Writing outside the project, in the only sense a rule can express.
 *
 * The obvious guardrail — "the agent wrote outside the project" — CANNOT BE WRITTEN.
 * A rule sees the tool and its path, not the project root, so "outside the project"
 * has nothing to compare against and would match everything or nothing. This
 * guardrail is therefore bounded to well-known ABSOLUTE paths, and says so in its own
 * description.
 *
 * The path is matched after `.` and `..` are resolved, and a relative or `~` path is
 * also matched resolved against the agent's working and home folders where the hook
 * is given them, so `/tmp/../etc/hosts` and `../../../etc/hosts` from a project both
 * land on `/etc/**`. Symbolic links are not followed: the decision is made before the
 * call runs, from the path alone. The one link every macOS machine has, `/etc` →
 * `/private/etc`, is named as a glob of its own.
 */
export const fsSystemPaths: Rule = {
  id: "fs.system-paths",
  category: "file-scope",
  severity: "high",
  defaultAction: "require_approval",
  owasp: ["ASI02", "LLM03"],
  title: "Writing to a system directory",
  description:
    "Holds a file tool writing to a path under a system directory — /etc (and /private/etc, which macOS links it to), /bin, /sbin, /usr/bin, /usr/local/bin, /boot, /System, /Library/LaunchDaemons, or Windows/System32. Reading is excluded — the Read and Grep tools never match — so reading /etc/hosts is not held; every other file tool is, including one this corpus does not know. The path is checked after '.' and '..' are resolved, and a relative or '~' path also after resolving it against the agent's working and home folders, so /tmp/../etc/hosts and ../../../etc/hosts written from a project are both held. CEILING: this is a list of well-known ABSOLUTE paths and it cannot be anything else. No project root reaches a rule, so the check you would actually want — 'the agent wrote outside the project' — is inexpressible, and would match everything or nothing. It therefore MISSES a write anywhere else outside your repository, including another project on the same machine. It also MISSES a path that only reaches a system directory through a symbolic link (a link in the project pointing at /etc), a Windows 8.3 short name such as PROGRA~1, and a relative path when the hook is given no working folder.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "/etc/**" },
      // macOS links `/etc` to `/private/etc`; `/tmp` and `/var` are not protected here.
      { kind: "execute_tool", file_glob: "/private/etc/**" },
      { kind: "execute_tool", file_glob: "/bin/**" },
      { kind: "execute_tool", file_glob: "/sbin/**" },
      { kind: "execute_tool", file_glob: "/usr/bin/**" },
      { kind: "execute_tool", file_glob: "/usr/local/bin/**" },
      { kind: "execute_tool", file_glob: "/boot/**" },
      { kind: "execute_tool", file_glob: "/System/**" },
      { kind: "execute_tool", file_glob: "/Library/LaunchDaemons/**" },
      { kind: "execute_tool", file_glob: "**/Windows/System32/**" },
    ],
    none_of: [
      // A read is not an edit. Named as a deny-list rather than an `any_of` over
      // the write tools, so an unknown file tool on a matched path still holds.
      { kind: "execute_tool", label: "{Read,Grep}" },
    ],
  },
  fixtures: {
    // Ordered so the first, middle and last of each list (the examples shown for a rule)
    // stay plain paths; the dot-segment cases sit between them.
    block: [
      file("/etc/hosts", "Write"),
      file("/usr/local/bin/app", "Write"),
      // Paths that only reach a system directory once '.' and '..' are resolved.
      file("/tmp/../etc/hosts", "Write"),
      file("/Users/dev/project/../../../etc/hosts", "Write"),
      file("/etc/./hosts", "Write"),
      file("/etc//hosts", "Write"),
      file("/private/etc/hosts", "Write"),
      file("/tmp/../bin/sh", "Write"),
      file("/tmp/../sbin/launchd", "Write"),
      file("/opt/../usr/bin/env", "Write"),
      file("/Library/LaunchDaemons/com.example.plist", "Write"),
      file("/tmp/../private/etc/hosts", "Write"),
      file("/var/../usr/local/bin/app", "Write"),
      file("/tmp/../boot/vmlinuz", "Write"),
      file("/tmp/../System/Library/x.plist", "Write"),
      file("/tmp/../Library/LaunchDaemons/com.example.plist", "Write"),
      file("C:\\Users\\dev\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", "Write"),
      file("C:\\..\\..\\Windows\\System32\\x.dll", "Write"),
      file("\\\\?\\C:\\Windows\\System32\\x.dll", "Write"),
      file("C:\\Windows\\System32.\\x.dll", "Write"),
      file("C:/Windows/System32/drivers/etc/hosts", "Write"),
    ],
    allow: [
      file("src/index.ts"),
      file("/home/dev/project/src/main.rs"),
      file("/tmp/scratch.txt", "Write"),
      // A '..' that stays inside the project, or climbs out of a system directory.
      file("/home/dev/project/src/../lib/main.rs", "Write"),
      file("/private/tmp/scratch.txt", "Write"),
      file("docs/etc-notes.md"),
      file("/etc/hosts", "Read"),
      file("/etc/../tmp/scratch.txt", "Write"),
      file("/tmp/../etc/hosts", "Read"),
      file("/private/var/folders/xy/T/scratch.txt", "Write"),
      file("/usr/local/bin/app", "Grep"),
    ],
  },
};
