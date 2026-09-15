/**
 * Pack: `test-integrity` — The agent making its work look successful.
 *
 * Deleting a test, weakening a runner's configuration, accepting every snapshot difference,
 * switching a coverage gate off, silencing type, lint or test failures in bulk, or telling CI not
 * to run. Each leaves a suite that reports green about code nobody checked.
 *
 * ── The pack's permanent ceiling ────────────────────────────────────────────
 *
 * File tools reach the guard with a path and no content. A test weakened with the Edit tool — an
 * assertion deleted, a `.skip` added, a type-check suppression inserted — is invisible here, and nothing in
 * this pack claims otherwise. Content is visible only on the command channel (`sed -i`, `perl -pi`),
 * and the one file rule, `ti.test-config-edit`, matches a runner's configuration by path without
 * seeing what changed.
 *
 * Mostly `warn`: regenerating snapshots, running without coverage and silencing a known false
 * positive are ordinary work. The two rules that ask are deleting a test and editing a runner's or
 * coverage tool's configuration.
 *
 * Six rules: five on the command channel, one on the file channel.
 */

import type { Rule } from "../../schema.js";
import { tiCiSkipMarker } from "./ti-ci-skip-marker.js";
import { tiCoverageBypass } from "./ti-coverage-bypass.js";
import { tiInlineSuppressBulk } from "./ti-inline-suppress-bulk.js";
import { tiSnapshotBlanketUpdate } from "./ti-snapshot-blanket-update.js";
import { tiTestConfigEdit } from "./ti-test-config-edit.js";
import { tiTestFileDelete } from "./ti-test-file-delete.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  tiTestFileDelete,
  tiTestConfigEdit,
  tiSnapshotBlanketUpdate,
  tiCoverageBypass,
  tiInlineSuppressBulk,
  tiCiSkipMarker,
];
