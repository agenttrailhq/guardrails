// cspell:words exfiltration
/**
 * Pack: `exfiltration` — Moving data off the machine, or opening a way in.
 *
 * A reverse shell, a public tunnel, a file upload, a paste service: four ways an agent sends what it
 * has read somewhere it should not go, or hands an outsider a route back in. This is the part of the
 * old network pack that never depended on the dropped `url` channel — every rule here is an ordinary
 * shell command, seen on the command channel.
 *
 * ── The pack's permanent ceiling ────────────────────────────────────────────
 *
 * Command channel only. An HTTP POST made through the `WebFetch` tool, or by an MCP server, is not a
 * shell command and is not seen here. An MCP tool call reaches the rules as its whole input
 * serialized into one JSON string, which does not start with a shell verb, so a command rule written
 * for shell syntax will not match it. Content, too, is invisible: these rules match the transport and
 * the destination, never what is being sent.
 *
 * `ex.reverse-shell` blocks; the other three ask, because a tunnel, an upload and a gist each have an
 * ordinary use often enough that a hold, not a refusal, is right.
 *
 * Four rules, all on the command channel.
 */

import type { Rule } from "../../schema.js";
import { exFileUpload } from "./ex-file-upload.js";
import { exPasteService } from "./ex-paste-service.js";
import { exReverseShell } from "./ex-reverse-shell.js";
import { exTunnelExpose } from "./ex-tunnel-expose.js";

/** Rules in this pack. */
export const rules: readonly Rule[] = [
  exReverseShell,
  exTunnelExpose,
  exFileUpload,
  exPasteService,
];
