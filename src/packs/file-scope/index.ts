/**
 * Pack: `file-scope` — The agent wrote somewhere it had no business writing.
 *
 * The distinction from `secret-exposure` is what the harm is ABOUT. A rule filed
 * by what is INSIDE the file — a private key, a cloud credential, a dotenv —
 * belongs there, because a user who disabled this pack to stop path noise would
 * otherwise silently lose their secret protection, which they never asked to turn
 * off and would not know they had. What is left here is a distinct damage: the
 * agent's own permissions, the machine, the repository's internals, the CI
 * definition.
 *
 * ── The pack's permanent ceiling ────────────────────────────────────────────
 *
 * The obvious rule — "the agent wrote outside the project" — CANNOT BE WRITTEN.
 * `MappedCall.args` is exactly `{full_command, file_path}` and `PreToolUsePayload`
 * is exactly `{tool_name, tool_input}`: no cwd, no project root, nothing to
 * compare a path against. Such a rule would match everything or nothing, which is
 * the dead-rule class `scope` is banned for. So every rule here matches a
 * WELL-KNOWN absolute or dot-prefixed path and nothing else, and each one says so
 * in its own description rather than leaving a reader to assume more.
 *
 * The guard installs per machine, so it also sees a developer's personal projects,
 * and it cannot tell them apart.
 *
 * Four rules. The other three `file_glob` rules are filed by harm in
 * `secret-exposure` and `prod-infra` instead.
 */

import type { Rule } from "../../schema.js";
import { fsAgentSelfConfig } from "./fs-agent-self-config.js";
import { fsCiDefinition } from "./fs-ci-definition.js";
import { fsSystemPaths } from "./fs-system-paths.js";
import { fsVcsInternals } from "./fs-vcs-internals.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  fsAgentSelfConfig,
  fsSystemPaths,
  fsVcsInternals,
  fsCiDefinition,
];
