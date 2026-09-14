import { PRINT_MENTION, SEARCH_MENTION } from "../../exemptions.js";
import {
  bash,
  mentionInCommit,
  mentionInEcho,
  mentionInPost,
  mentionInSearch,
} from "../../fixtures.js";
import type { Rule } from "../../schema.js";

export const blockHardcodedSecrets: Rule = {
  id: "block-hardcoded-secrets",
  category: "secret-exposure",
  severity: "critical",
  defaultAction: "block",
  title: "Block hard-coded secrets in commands",
  description:
    "Blocks a shell command carrying a credential with the right SHAPE — an AWS access-key id (AKIA/ASIA plus 16 more characters), a GitHub token (gh?_ with a body of at least 36 characters, or github_pat_ with a long one), a Stripe live key, or PEM PRIVATE key material. Three arms are CASE-SENSITIVE and use detail_contains deliberately: these prefixes are upper- or lower-case by specification, so case IS the signal, and the length check in the same condition is what makes the difference between a mention and a key. Requiring the body is why auditing your own repo for a leak (`grep -rn AKIA .`) is not itself blocked, and requiring PRIVATE KEY beside -----BEGIN is why a public certificate is not. MISSES formats not listed (Slack, OpenAI, Google) and any secret that is not self-identifying, such as a bare password; and it sees command text only, never the contents of a file edit. A quoted MENTION is exempt on only TWO of the four carriers this corpus recognises, and this is the one rule where they are not equivalent — because here the carrier IS the exposure rather than a mention of it. A search (`grep -rn AKIA .`) and an `echo` are exempt: the key goes nowhere, and searching for one is how you find it to rotate. A `git commit -m` message and a `curl --data` body are NOT: a key in a commit message is written into history and then pushed, and a key in a POST body has already left the machine. The cost of that, stated in the other direction: documenting a REAL-looking key in a commit message is still blocked, and the only ways through are to redact the body of the key or to use a placeholder that fails the length check. Exemption also holds only while every shell metacharacter stays inside the quotes, and a single leading `sudo` aside, the carrier must be the first word.",
  match: {
    any_of: [
      { kind: "execute_tool", detail_contains: ["AKIA"], detail_matches: ["AKIA[0-9A-Z]{16}"] },
      { kind: "execute_tool", detail_contains: ["ASIA"], detail_matches: ["ASIA[0-9A-Z]{16}"] },
      {
        kind: "execute_tool",
        detail_matches: ["\\bgh[opsur]_[a-z0-9]{36,}\\b", "\\bgithub_pat_[a-z0-9_]{50,}"],
      },
      {
        kind: "execute_tool",
        detail_contains: ["sk_live_"],
        detail_matches: ["sk_live_[a-z0-9]{16,}"],
      },
      { kind: "execute_tool", detail_contains: ["-----BEGIN ", "PRIVATE KEY"] },
    ],
    // Only TWO of the four carriers are exempt here, and this is the one rule where
    // that is true. For every other rule a carrier is inert — a commit message naming
    // `rm -rf /` deletes nothing. Here the carrier IS the exposure: a live key in a
    // commit message is written into history and pushed, and a live key in a POST
    // body has already left the machine. Searching for a key is how you find one to
    // rotate, and printing one is transient terminal output; those two stay exempt.
    none_of: [SEARCH_MENTION, PRINT_MENTION],
  },
  fixtures: {
    block: [
      bash("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
      bash(`export AWS_ACCESS_KEY_ID=ASIA${"EXAMPLE".repeat(3).slice(0, 16)}`),
      bash(`export GH_TOKEN=ghp_${"EXAMPLE".repeat(6)}`),
      bash("ssh-add - <<< '-----BEGIN OPENSSH PRIVATE KEY-----'"),
      // The carrier rule above, as fixtures. These two are `block` — MUST
      // match — precisely because they are quoted mentions, which everywhere else
      // in this corpus means "leave it alone".
      mentionInCommit("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
      mentionInPost("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
    ],
    allow: [
      mentionInSearch("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
      mentionInEcho("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
      bash("grep -rn AKIA ."),
      bash("rg ghp_ --glob '!node_modules'"),
      bash("openssl x509 -in certs/server.pem -text"),
      bash("export NODE_ENV=production"),
    ],
  },
};
