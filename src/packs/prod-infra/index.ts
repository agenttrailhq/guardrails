// cspell:words kubeconfig
/**
 * Pack: `prod-infra` — Changes to running infrastructure and to production.
 *
 * The honest ceiling of this whole pack: the guard sees ONE tool call and nothing
 * else. No kubeconfig, no AWS profile, no `TF_WORKSPACE`, no current git branch.
 * So "is this production" can only be answered when the COMMAND ITSELF says so,
 * which is what `pi.prod-namespace` and `pi.deploy-to-prod` do. The rest of the
 * pack matches the dangerous verb regardless of environment and holds it for
 * approval, which is why almost nothing here is `block`.
 *
 * Eight rules, including `block-prod-config-edit`, filed by harm rather than by
 * matcher.
 */

import type { Rule } from "../../schema.js";
import { blockProdConfigEdit } from "./block-prod-config-edit.js";
import { piCloudResourceDelete } from "./pi-cloud-resource-delete.js";
import { piDeployToProd } from "./pi-deploy-to-prod.js";
import { piHelmRelease } from "./pi-helm-release.js";
import { piKubectlDelete } from "./pi-kubectl-delete.js";
import { piProdNamespace } from "./pi-prod-namespace.js";
import { piTerraformAutoApprove } from "./pi-terraform-auto-approve.js";
import { piTerraformStateMutate } from "./pi-terraform-state-mutate.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  piTerraformAutoApprove,
  piTerraformStateMutate,
  piKubectlDelete,
  piProdNamespace,
  piHelmRelease,
  piCloudResourceDelete,
  piDeployToProd,
  blockProdConfigEdit,
];
