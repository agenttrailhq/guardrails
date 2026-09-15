/**
 * Pack: `agent-context` — The agent changing what it is, what it knows, or how many of it there are.
 *
 * The standing instructions an agent reads at the start of every session, the memory it carries
 * between sessions, the skills, commands and sub-agents it can load, the MCP servers it can call,
 * the other agents it starts, and the approval settings those agents run with.
 *
 * The distinction from `file-scope` is permissions versus goals. `fs.agent-self-config` holds the
 * files that define what an agent is ALLOWED to do: settings, hooks, MCP server lists. This pack
 * holds the files and commands that change what an agent is TOLD to do and what it REMEMBERS, which
 * is why `.claude/commands/*.md` is excluded there and matched here.
 *
 * ── The pack's permanent ceiling ────────────────────────────────────────────
 *
 * The guard sees the resulting action, not the instruction that caused it. A prompt injection that
 * stays inside one conversation is invisible here; the durable version of it — a line written into
 * `CLAUDE.md`, a new skill, a memory entry, a newly added MCP server, an agent started with its
 * approvals switched off — is what these rules catch. File tools reach the guard with a path and no
 * content, so every file rule here matches a WELL-KNOWN path and cannot see what was written.
 *
 * Six rules: three match paths on the file channel and three match commands. `ac.mcp-server-add`
 * also holds Cursor's `.cursor/mcp.json` as a path, because Cursor has no command for adding a server.
 */

import type { Rule } from "../../schema.js";
import { acAgentAutonomyFlag } from "./ac-agent-autonomy-flag.js";
import { acInstructionFileEdit } from "./ac-instruction-file-edit.js";
import { acMcpServerAdd } from "./ac-mcp-server-add.js";
import { acMemoryStoreEdit } from "./ac-memory-store-edit.js";
import { acRecursiveAgentInvoke } from "./ac-recursive-agent-invoke.js";
import { acSkillInstall } from "./ac-skill-install.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  acInstructionFileEdit,
  acMemoryStoreEdit,
  acSkillInstall,
  acMcpServerAdd,
  acRecursiveAgentInvoke,
  acAgentAutonomyFlag,
];
