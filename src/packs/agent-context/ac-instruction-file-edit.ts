// cspell:words clinerules cursorrules windsurfrules
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * The standing instructions a coding agent loads at the start of every session.
 *
 * A line written here is followed by every later session, which is how a one-off prompt injection
 * becomes permanent. Several tools now read each other's files — Cursor, Windsurf, Copilot and
 * Cline all read `AGENTS.md`, and Cursor and Copilot read `CLAUDE.md` — so each glob protects
 * more than the tool its name suggests.
 */
export const acInstructionFileEdit: Rule = {
  id: "ac.instruction-file-edit",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "The agent editing its standing instructions",
  description:
    "Holds a file tool opening the instructions a coding agent loads at the start of every session: `CLAUDE.md`, `CLAUDE.local.md` and `.claude/rules/`; `AGENTS.md` and `AGENTS.override.md`, which Codex, Cursor, Windsurf, Copilot and Cline all read; `GEMINI.md`; `.cursorrules`; Windsurf's `.windsurfrules`, `.windsurf/rules/` and `.devin/rules/`; Cline's `.clinerules` file or directory and its global `Cline/Rules/` folder; Copilot's `.github/copilot-instructions.md` and `.github/instructions/**/*.instructions.md`; and `.aider.conf.yml`, which sets the files Aider reads on every launch. A line written into one of these is followed in every later session. Matched in any directory and in any letter case. File tools carry a path and no content, so it cannot see what was written, and it does not tell reading apart from editing. Does not cover `.cursor/rules/`, which `fs.agent-self-config` holds. Misses a context file renamed through Gemini's `context.fileName` or Codex's `project_doc_fallback_filenames`, Aider's `CONVENTIONS.md`, which Aider loads only when asked and which is too common a name to match, and any of these files written by a shell command instead of a file tool.",
  match: {
    any_of: [
      {
        kind: "execute_tool",
        file_glob: "**/{CLAUDE,CLAUDE.local,AGENTS,AGENTS.override,GEMINI}.md",
      },
      { kind: "execute_tool", file_glob: "**/.claude/rules/**" },
      { kind: "execute_tool", file_glob: "**/.{cursorrules,windsurfrules}" },
      { kind: "execute_tool", file_glob: "**/.{windsurf,devin}/rules/**" },
      { kind: "execute_tool", file_glob: "**/.clinerules" },
      { kind: "execute_tool", file_glob: "**/.clinerules/**" },
      { kind: "execute_tool", file_glob: "**/Cline/Rules/**" },
      { kind: "execute_tool", file_glob: "**/.github/copilot-instructions.md" },
      { kind: "execute_tool", file_glob: "**/.github/instructions/**/*.instructions.md" },
      { kind: "execute_tool", file_glob: "**/.aider.conf.yml" },
    ],
  },
  fixtures: {
    block: [
      file("CLAUDE.md"),
      file("packages/api/CLAUDE.md", "Write"),
      file("CLAUDE.local.md"),
      file(".claude/rules/testing.md", "Write"),
      file("AGENTS.md"),
      file("services/billing/AGENTS.override.md"),
      file("/home/dev/.gemini/GEMINI.md", "Write"),
      file(".cursorrules"),
      file(".windsurfrules"),
      file(".windsurf/rules/style.md"),
      file(".devin/rules/style.md"),
      file(".clinerules"),
      file(".clinerules/coding.md", "Write"),
      file("/Users/dev/Documents/Cline/Rules/global.md", "Write"),
      file(".github/copilot-instructions.md"),
      file(".github/instructions/frontend/react.instructions.md"),
      file(".aider.conf.yml"),
      file("docs/claude.md"),
    ],
    allow: [
      file("README.md"),
      file("CLAUDE.md.bak"),
      file("CONVENTIONS.md"),
      file("docs/agents/overview.md"),
      file("src/agents.ts"),
      file("docs/rules/style.md"),
      file(".github/PULL_REQUEST_TEMPLATE.md"),
      file(".github/workflows/ci.yml"),
      file(".cursor/rules/style.mdc"),
      file(".claude/settings.json"),
      file(".aider.chat.history.md"),
    ],
  },
};
