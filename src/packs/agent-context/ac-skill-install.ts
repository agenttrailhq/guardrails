// cspell:words clinerules
import { file } from "../../fixtures.js";
import type { Rule } from "../../schema.js";

/**
 * Skills, slash commands, sub-agents and output styles: named instructions an agent loads later.
 *
 * `fs.agent-self-config` deliberately leaves `.claude/commands/*.md` alone, because a command is a
 * prompt rather than a permission. This rule is where that prompt is held. Several tools load each
 * other's folders — Cursor reads `.claude/` and `.codex/` skills and agents, and Windsurf, Gemini
 * and Cline read `.agents/skills/` — so each glob protects more than one tool.
 */
export const acSkillInstall: Rule = {
  id: "ac.skill-install",
  category: "agent-context",
  severity: "high",
  defaultAction: "require_approval",
  title: "The agent installing a skill, command or sub-agent",
  description:
    "Holds a file tool opening a skill, slash command, sub-agent or output style that a coding agent loads by name: Claude Code's `.claude/skills/`, `.claude/commands/`, `.claude/agents/` and `.claude/output-styles/`; the shared `.agents/skills/`; Codex's `.codex/skills/`, `.codex/prompts/` and `.codex/agents/`; Gemini's `.gemini/commands/`, `.gemini/skills/` and `.gemini/agents/`; Cursor's `.cursor/skills/`, `.cursor/agents/` and `.cursor/commands/`; Windsurf's `.windsurf/workflows/` and `.windsurf/skills/` and their global copies under `.codeium/windsurf/`; Cline's `.cline/skills/`; and a `SKILL.md` anywhere, which is how a plugin ships a skill. Each becomes a reusable instruction the agent may follow later, often with a script beside it that the agent runs. Matched at project or home level and in any letter case. File tools carry a path and no content, so it cannot see what was written, and it does not tell reading apart from editing. Deliberately NOT matched: an ordinary `skills/`, `commands/` or `agents/` folder in a project's source, and `.clinerules/skills/`, which `ac.instruction-file-edit` holds. Misses a skill copied into one of these folders by a shell command such as `cp` or `git clone`, and the managed system-wide workflow folders.",
  match: {
    any_of: [
      { kind: "execute_tool", file_glob: "**/.claude/{skills,commands,agents,output-styles}/**" },
      { kind: "execute_tool", file_glob: "**/.agents/skills/**" },
      { kind: "execute_tool", file_glob: "**/.codex/{skills,prompts,agents}/**" },
      { kind: "execute_tool", file_glob: "**/.gemini/{commands,skills,agents}/**" },
      { kind: "execute_tool", file_glob: "**/.cursor/{skills,agents,commands}/**" },
      { kind: "execute_tool", file_glob: "**/.windsurf/{workflows,skills}/**" },
      { kind: "execute_tool", file_glob: "**/.codeium/windsurf/{skills,global_workflows}/**" },
      { kind: "execute_tool", file_glob: "**/.cline/skills/**" },
      { kind: "execute_tool", file_glob: "**/SKILL.md" },
    ],
  },
  fixtures: {
    block: [
      file(".claude/skills/deploy/SKILL.md", "Write"),
      file(".claude/commands/deploy.md"),
      file(".claude/agents/reviewer.md", "Write"),
      file("/Users/dev/.claude/skills/release/scripts/publish.sh", "Write"),
      file(".claude/output-styles/terse.md"),
      file(".agents/skills/lint/SKILL.md"),
      file("/home/dev/.codex/prompts/refactor.md", "Write"),
      file(".codex/skills/migrate/SKILL.md"),
      file(".gemini/commands/git/commit.toml"),
      file(".gemini/agents/security.md"),
      file(".cursor/agents/security.md"),
      file(".windsurf/workflows/release.md"),
      file("/home/dev/.codeium/windsurf/global_workflows/triage.md"),
      file(".cline/skills/db/SKILL.md"),
      file("plugins/tools/skills/format/SKILL.md", "Write"),
    ],
    allow: [
      file("README.md"),
      file("SKILLS.md"),
      file("docs/skills/overview.md"),
      file("src/commands/deploy.ts"),
      file("src/agents/planner.ts"),
      file(".claude/settings.json"),
      file(".github/workflows/release.yml"),
      file("scripts/release.sh"),
      file(".gemini/settings.json"),
    ],
  },
};
