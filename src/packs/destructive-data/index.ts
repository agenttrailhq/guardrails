/**
 * Pack: `destructive-data` — Irrecoverable loss of data that lives outside git.
 *
 * The distinction from `working-tree` is what git can undo. A bad `git reset
 * --hard` loses uncommitted edits; a dropped volume, a dropped database or a
 * deleted shadow copy loses everything, and no reflog helps.
 *
 * Eight rules, including `block-destructive-sql`, filed here by harm —
 * irrecoverable data loss is this pack's whole subject.
 */

import type { Rule } from "../../schema.js";
import { blockDestructiveSql } from "./block-destructive-sql.js";
import { ddAcceptDataLoss } from "./dd-accept-data-loss.js";
import { ddDatabaseDrop } from "./dd-database-drop.js";
import { ddDockerPruneVolumes } from "./dd-docker-prune-volumes.js";
import { ddDockerVolumeDestroy } from "./dd-docker-volume-destroy.js";
import { ddMigrationReset } from "./dd-migration-reset.js";
import { ddRmRfAbsolute } from "./dd-rm-rf-absolute.js";
import { ddShadowCopyDelete } from "./dd-shadow-copy-delete.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  ddRmRfAbsolute,
  ddDockerVolumeDestroy,
  ddDockerPruneVolumes,
  ddDatabaseDrop,
  ddMigrationReset,
  ddAcceptDataLoss,
  ddShadowCopyDelete,
  blockDestructiveSql,
];
