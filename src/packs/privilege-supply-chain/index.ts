/**
 * Pack: `privilege-supply-chain` — Gaining reach, or handing it to something else.
 *
 * Writing as root, opening a file to every account, granting an IAM role,
 * arranging to run again tomorrow, publishing to a registry, pulling in a new
 * dependency. None of them destroys anything at the moment it happens; each of
 * them changes what is possible afterwards, which is why the whole pack holds or
 * warns rather than blocks.
 *
 * Six rules, including `flag-dependency-install`.
 */

import type { Rule } from "../../schema.js";
import { flagDependencyInstall } from "./flag-dependency-install.js";
import { psIamGrant } from "./ps-iam-grant.js";
import { psPermissionWiden } from "./ps-permission-widen.js";
import { psPersistence } from "./ps-persistence.js";
import { psPublishArtifact } from "./ps-publish-artifact.js";
import { psSudoWrite } from "./ps-sudo-write.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  psSudoWrite,
  psPermissionWiden,
  psIamGrant,
  psPersistence,
  psPublishArtifact,
  flagDependencyInstall,
];
