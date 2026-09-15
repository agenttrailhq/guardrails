/**
 * Pack: `safety-bypass` — Turning off the checks somebody installed on purpose.
 *
 * Nothing in this pack is destructive by itself. Each rule catches the moment a
 * safety net is removed, which is what makes the NEXT action dangerous — and
 * which is why every one of them holds for approval rather than blocks: each is
 * also, occasionally, the right thing to do.
 *
 * Seven rules.
 */

import type { Rule } from "../../schema.js";
import { gbAdminMerge } from "./gb-admin-merge.js";
import { gbAnsiTerminalForgery } from "./gb-ansi-terminal-forgery.js";
import { gbAuditTrailPurge } from "./gb-audit-trail-purge.js";
import { gbExecutionPolicyBypass } from "./gb-execution-policy-bypass.js";
import { gbGitNoVerify } from "./gb-git-no-verify.js";
import { gbHooksDisable } from "./gb-hooks-disable.js";
import { gbHostKeyBypass } from "./gb-host-key-bypass.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  gbGitNoVerify,
  gbAdminMerge,
  gbHooksDisable,
  gbHostKeyBypass,
  gbExecutionPolicyBypass,
  gbAuditTrailPurge,
  gbAnsiTerminalForgery,
];
