import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The memory an agent carries from one session to the next.
 *
 * A false fact saved here is recalled as true later, with nothing marking where it came from.
 * Every glob is scoped to a directory the agent itself owns: the file name `MEMORY.md` alone is
 * not an agent's memory, and a project's own notes folder must not ask for approval.
 */
export const acMemoryStoreEdit: Rule = {
  id: "ac.memory-store-edit",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "The agent editing its own memory",
  description:
    "Holds a file tool opening the memory a coding agent carries between sessions: Claude Code's auto memory under `.claude/projects/<project>/memory/`, and its sub-agent memory in `.claude/agent-memory/` and `.claude/agent-memory-local/`; Codex's `.codex/memories/`; Gemini's private `.gemini/tmp/<project>/memory/`; Windsurf's `.codeium/windsurf/memories/`, including `global_rules.md`; and `.cursor/memory/`. A false fact saved here is recalled as true in every later session. A `MEMORY.md` outside those directories deliberately does NOT match, and neither does a project's own `docs/memory/` folder: the name alone is not an agent's memory. File tools carry a path and no content, so it cannot see what was written, and it does not tell reading apart from editing, so an agent recalling a memory by reading its file is asked too. Misses a memory directory moved with Claude Code's `autoMemoryDirectory` setting, and Cursor memories kept anywhere other than `.cursor/memory/`, since Cursor does not document where it stores them. Gemini memories saved into `GEMINI.md` are held by `ac.instruction-file-edit` instead.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.claude/projects/*/memory/**" },
      { kind: "execute_tool", file_glob: "**/.claude/{agent-memory,agent-memory-local}/**" },
      { kind: "execute_tool", file_glob: "**/.codex/memories/**" },
      { kind: "execute_tool", file_glob: "**/.gemini/tmp/*/memory/**" },
      { kind: "execute_tool", file_glob: "**/.codeium/windsurf/memories/**" },
      { kind: "execute_tool", file_glob: "**/.cursor/memory/**" },
    ],
  },
  fixtures: {
    block: [
      file("/Users/dev/.claude/projects/-Users-dev-shop/memory/MEMORY.md", "Write"),
      file("/Users/dev/.claude/projects/-Users-dev-shop/memory/deploy-steps.md", "Write"),
      file(".claude/agent-memory/reviewer/MEMORY.md"),
      file(".claude/agent-memory-local/reviewer/notes.md", "Write"),
      file("/home/dev/.claude/agent-memory/planner/MEMORY.md"),
      file("/home/dev/.codex/memories/project.md", "Write"),
      file("/home/dev/.gemini/tmp/3f9a2c/memory/MEMORY.md"),
      file("/home/dev/.cache/.gemini/tmp/3f9a2c/memory/MEMORY.md", "Write"),
      file("/home/dev/.codeium/windsurf/memories/global_rules.md"),
      file(".cursor/memory/notes.md"),
    ],
    allow: [
      file("MEMORY.md"),
      file("docs/MEMORY.md"),
      file("docs/memory/notes.md"),
      file("src/memory/cache.ts"),
      file("packages/memory-store/src/index.ts"),
      file("/Users/dev/.claude/projects/-Users-dev-shop/transcript.jsonl"),
      file("/home/dev/.gemini/settings.json"),
      file(".claude/settings.json"),
    ],
  },
};
