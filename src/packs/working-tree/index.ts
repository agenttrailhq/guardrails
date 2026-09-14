/**
 * Pack: `working-tree` — Destructive git and filesystem operations against the working tree.
 *
 * This pack leads the catalog: destructive git commands are the most frequently
 * documented coding-agent failure, with public incident reports across Claude
 * Code, Gemini CLI and Codex.
 *
 * Nine rules: the seven `wt.*` rules, plus two filed here BY HARM —
 * `block-force-push` destroys published history, and `require-approval-rm-rf` is
 * filesystem destruction against the tree, which is what this pack is about.
 */

import type { Rule } from "../../schema.js";
import { blockForcePush } from "./block-force-push.js";
import { requireApprovalRmRf } from "./require-approval-rm-rf.js";
import { wtBranchForceDelete } from "./wt-branch-force-delete.js";
import { wtCheckoutDiscard } from "./wt-checkout-discard.js";
import { wtCleanFdx } from "./wt-clean-fdx.js";
import { wtResetHard } from "./wt-reset-hard.js";
import { wtResetMerge } from "./wt-reset-merge.js";
import { wtRestorePath } from "./wt-restore-path.js";
import { wtStashDrop } from "./wt-stash-drop.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  wtResetHard,
  wtCheckoutDiscard,
  wtRestorePath,
  wtStashDrop,
  wtBranchForceDelete,
  wtCleanFdx,
  wtResetMerge,
  blockForcePush,
  requireApprovalRmRf,
];
