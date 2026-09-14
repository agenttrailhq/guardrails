/**
 * Pack: `secret-exposure` — Credentials and sensitive data leaving where they live.
 *
 * The pack's largest, at ten rules, and the one whose actions are mostly `warn`.
 * That is deliberate: reading a secret is a normal part of a normal day, and a
 * pack that holds every one of them is a pack a team disables on day two. Only
 * the two rules about data actually LEAVING — `se.secret-egress` and
 * `se.public-acl` — hold, along with the credential-file and endpoint rules.
 *
 * Four rules are filed here BY HARM rather than by matcher:
 * `block-hardcoded-secrets` (credential material in a command),
 * `block-env-file-read` and `require-auth-on-pii-endpoints` (both `file_glob`
 * rules, filed by what they protect rather than by the fact that they match a
 * path), and `warn-op-read-secret`.
 */

import type { Rule } from "../../schema.js";
import { blockEnvFileRead } from "./block-env-file-read.js";
import { blockHardcodedSecrets } from "./block-hardcoded-secrets.js";
import { requireAuthOnPiiEndpoints } from "./require-auth-on-pii-endpoints.js";
import { seCredentialFile } from "./se-credential-file.js";
import { seEnvPrint } from "./se-env-print.js";
import { sePublicAcl } from "./se-public-acl.js";
import { seSecretEgress } from "./se-secret-egress.js";
import { seSecretManagerRead } from "./se-secret-manager-read.js";
import { seTokenPrint } from "./se-token-print.js";
import { warnOpReadSecret } from "./warn-op-read-secret.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  seSecretManagerRead,
  seEnvPrint,
  seSecretEgress,
  seCredentialFile,
  seTokenPrint,
  sePublicAcl,
  blockHardcodedSecrets,
  blockEnvFileRead,
  requireAuthOnPiiEndpoints,
  warnOpReadSecret,
];
