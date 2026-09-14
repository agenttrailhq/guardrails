/**
 * Pack: `rce-supply-chain` — Running code nobody reviewed.
 *
 * The five shapes: pipe it into a shell, substitute it into one, run it straight
 * from a URL, fetch it from a registry somebody redirected, or fetch it over a
 * connection whose certificate is not checked. Every rule here holds rather than
 * blocks, because every one of them is also how legitimate software gets
 * installed.
 *
 * Six rules, including `block-curl-pipe-to-shell` — executing an unreviewed
 * remote script is the pack's subject.
 */

import type { Rule } from "../../schema.js";
import { blockCurlPipeToShell } from "./block-curl-pipe-to-shell.js";
import { rceEvalDynamic } from "./rce-eval-dynamic.js";
import { rceForeignRegistry } from "./rce-foreign-registry.js";
import { rceRemoteRunner } from "./rce-remote-runner.js";
import { rceTlsVerifyOff } from "./rce-tls-verify-off.js";
import { rceUnverifiedPackage } from "./rce-unverified-package.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  rceEvalDynamic,
  rceRemoteRunner,
  rceForeignRegistry,
  rceTlsVerifyOff,
  rceUnverifiedPackage,
  blockCurlPipeToShell,
];
